"""
routes_analyze.py — REST endpoint for audio file analysis.

POST /api/analyze
  Accepts an uploaded audio file (WAV, MP3, FLAC, video containers, etc.)
  Runs the full detection pipeline
  Returns risk score, alert level, and recommendation

Design:
  - Upload is streamed to a temp file in bounded chunks rather than read entirely
    into RAM. This prevents memory exhaustion from large files.
  - The configured max_duration_sec is enforced after audio decode.
  - All temporary files are cleaned up in finally blocks.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import os
import tempfile
import uuid
import hashlib
import time
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from typing import Optional, List
from sqlalchemy.orm import Session

from backend.storage.auth import get_optional_user, require_user
from backend.storage.database import (
    get_db_session,
    AnalysisRecordModel,
    ReviewQueueModel,
    ModelVersionModel,
    UserModel,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Analysis"])

# Streaming chunk size for upload-to-disk (64 KB per read)
_UPLOAD_CHUNK_BYTES = 65536


class AnalysisResponse(BaseModel):
    session_id: str
    filename: str
    total_chunks: int
    peak_risk: float
    mean_risk: float
    final_risk: float
    alert_level: str
    recommendation: dict
    chunk_scores: list
    processing_time_ms: float
    detector_version: str = "v001"
    external_intelligence: Optional[dict] = None


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_audio_file(
    file: UploadFile = File(...),
    speaker_id: Optional[str] = Form(None),
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db_session),
):
    """
    Analyze an uploaded audio file for voice cloning.

    Returns:
      - risk score per chunk
      - overall peak and mean risk
      - alert level and recommendation
    """
    from backend.main import get_app_detector, app_settings
    from backend.audio.preprocessor import load_audio, preprocess_audio, chunk_audio
    from backend.detection.risk_engine import build_risk_engine_from_settings
    from backend.detection.speaker_consistency import SpeakerConsistencyChecker
    from backend.detection.threshold_engine import ThresholdEngine
    from backend.storage.speaker_registry import SpeakerRegistry
    from backend.threats.virustotal import VirusTotalProvider
    import time

    # Always fetch via getter so we get the live singleton
    app_detector = get_app_detector()

    if app_detector is None:
        raise HTTPException(
            status_code=503,
            detail="Detection subsystem not yet created. Please wait a moment and retry."
        )

    if not app_detector.is_initialized:
        logger.warning("Detector not initialized at request time — attempting lazy init...")
        try:
            app_detector.initialize()
            logger.info("Lazy detector initialization succeeded.")
        except Exception as exc:
            logger.error(f"Lazy detector initialization failed: {exc}")
            raise HTTPException(
                status_code=503,
                detail="Detector initialization failed. Please check server logs and retry."
            )

    session_id = str(uuid.uuid4())[:12]
    t_start = time.perf_counter()

    def _stage(label: str, t_prev: float) -> float:
        """Log elapsed time for a pipeline stage and return current timestamp."""
        now = time.perf_counter()
        logger.info(
            f"analysis_id={session_id} stage={label} "
            f"duration_ms={int((now - t_prev) * 1000)} status=done"
        )
        return now

    tmp_path: Optional[str] = None

    try:
        t0 = time.perf_counter()

        # ── Stream upload to temp file (avoids reading entire file into RAM) ──────
        max_bytes = app_settings.upload.max_file_size_bytes

        fd, tmp_path = tempfile.mkstemp(suffix=".dat")
        os.close(fd)

        bytes_written = 0
        sha256_hash = hashlib.sha256()
        
        with open(tmp_path, "wb") as out_f:
            while True:
                chunk_data = await file.read(_UPLOAD_CHUNK_BYTES)
                if not chunk_data:
                    break
                sha256_hash.update(chunk_data)
                bytes_written += len(chunk_data)
                if bytes_written > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            f"Uploaded file exceeds the maximum allowed size of "
                            f"{max_bytes // (1024 * 1024)} MB."
                        ),
                    )
                out_f.write(chunk_data)
                
        file_hash_hex = sha256_hash.hexdigest()
        t0 = _stage("upload", t0)

        # ── Media normalization (audio/video → MP3) ───────────────────────────────
        mp3_path: Optional[str] = None
        try:
            from backend.audio.preprocessor import normalize_to_mp3
            mp3_path = normalize_to_mp3(tmp_path)
            if mp3_path != tmp_path:
                # Delete original; mp3_path is now the working file
                os.unlink(tmp_path)
                tmp_path = mp3_path
                mp3_path = None  # ownership transferred to tmp_path
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Audio format error: {exc}")
        t0 = _stage("media_normalize", t0)

        # ── Load and preprocess ───────────────────────────────────────────────────
        try:
            audio, sr = load_audio(tmp_path, target_sr=app_settings.audio.sample_rate)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=f"Could not decode audio file: {exc}")
        t0 = _stage("audio_load", t0)

        # ── Duration enforcement ──────────────────────────────────────────────────
        max_dur = app_settings.upload.max_duration_sec
        if max_dur > 0:
            actual_duration = len(audio) / app_settings.audio.sample_rate
            if actual_duration > max_dur:
                raise HTTPException(
                    status_code=422,
                    detail=(
                        f"Audio duration ({actual_duration:.1f}s) exceeds the maximum "
                        f"allowed duration of {max_dur:.0f}s. "
                        "Please upload a shorter file."
                    ),
                )

        audio = preprocess_audio(
            audio, sr=app_settings.audio.sample_rate,
            target_sr=app_settings.audio.sample_rate,
            apply_vad=True,
        )
        chunks = chunk_audio(
            audio,
            sr=app_settings.audio.sample_rate,
            chunk_duration=app_settings.audio.chunk_duration_sec,
            overlap_ratio=app_settings.audio.overlap_ratio,
        )
        t0 = _stage("preprocess_chunk", t0)

        if not chunks:
            raise HTTPException(status_code=422, detail="No audio content found in file.")

        # ── Per-request detection components ──────────────────────────────────────
        risk_engine = build_risk_engine_from_settings(app_settings)
        consistency_checker = SpeakerConsistencyChecker(
            threshold=app_settings.speaker.consistency_threshold
        )
        threshold_engine = ThresholdEngine(
            threshold_low=app_settings.risk.alert_thresholds.low,
            threshold_medium=app_settings.risk.alert_thresholds.medium,
            threshold_high=app_settings.risk.alert_thresholds.high,
            threshold_critical=app_settings.risk.alert_thresholds.critical,
        )

        # Load speaker profile if specified
        if speaker_id:
            registry = SpeakerRegistry(
                db_path=str(app_settings.abs_path(app_settings.storage.db_path))
            )
            enrolled_emb = registry.get_embedding(speaker_id)
            if enrolled_emb is not None:
                consistency_checker.set_enrolled_profile(enrolled_emb, speaker_id)
        t0 = _stage("setup", t0)

        # ── Run detection pipeline (offloaded to thread pool) ─────────────────────
        loop = asyncio.get_event_loop()
        chunk_scores = []

        logger.info(
            f"analysis_id={session_id} stage=model_inference "
            f"chunks={len(chunks)} status=start"
        )
        for i, chunk in enumerate(chunks):
            result = await loop.run_in_executor(
                None,
                functools.partial(app_detector.process_chunk, chunk, chunk_id=i)
            )
            speaker_sim = None
            if result.speaker_embedding is not None:
                c_result = consistency_checker.check(result.speaker_embedding)
                speaker_sim = c_result.get("similarity")

            snapshot = risk_engine.update(
                chunk_id=i,
                detection_score=result.synthetic_probability,
                speaker_similarity=speaker_sim,
            )

            chunk_scores.append({
                "chunk_id": i,
                "detection_score": result.synthetic_probability,
                "risk_score": snapshot.combined_risk,
                "alert_level": snapshot.alert_level.value,
                "processing_ms": result.processing_time_ms,
            })
        t0 = _stage("model_inference", t0)

        summary = risk_engine.get_session_summary()
        final_risk = chunk_scores[-1]["risk_score"] if chunk_scores else 0.0
        
        # ── VirusTotal Hash Lookup (concurrent, non-blocking) ─────────────────────
        # Start VT lookup as a background task concurrently with risk calculation.
        # We then await it with a short timeout so it never blocks the response
        # more than 'timeout_sec' even if the VT service is slow.
        vt_result = None
        vt_provider = VirusTotalProvider(app_settings)
        if vt_provider.is_configured:
            vt_task = asyncio.ensure_future(vt_provider.get_file_report(file_hash_hex))
            try:
                vt_result = await asyncio.wait_for(
                    vt_task,
                    timeout=min(app_settings.virustotal.timeout_sec, 5.0),
                )
                if vt_result.get("status") == "COMPLETED":
                    malicious = vt_result.get("malicious_count", 0)
                    suspicious = vt_result.get("suspicious_count", 0)
                    if malicious > 0 or suspicious > 0:
                        vt_risk = min(1.0, (malicious * 0.1) + (suspicious * 0.05))
                        final_risk = min(1.0, final_risk + vt_risk)
                        summary["peak_risk"] = max(summary["peak_risk"], final_risk)
            except asyncio.TimeoutError:
                logger.warning(
                    f"analysis_id={session_id} stage=virustotal "
                    f"status=timeout duration_ms={int(app_settings.virustotal.timeout_sec * 1000)}"
                )
                vt_result = {"status": "TIMEOUT"}
            except Exception as exc:
                logger.warning(f"analysis_id={session_id} stage=virustotal status=error error={exc}")
                vt_result = {"status": "FAILED"}
        t0 = _stage("virustotal", t0)
        
        recommendation = threshold_engine.evaluate(summary["peak_risk"])

        t_end = time.perf_counter()
        total_ms = (t_end - t_start) * 1000
        logger.info(
            f"analysis_id={session_id} stage=complete "
            f"total_duration_ms={int(total_ms)} chunks={len(chunks)} "
            f"peak_risk={summary['peak_risk']:.4f} alert={recommendation.alert_level.value}"
        )

        # ── Cross-Pipeline Incident Recording & Alert Dispatch ───────────────────
        from backend.main import get_app_incident_manager, get_app_alert_manager
        inc_manager = get_app_incident_manager()
        alert_mgr = get_app_alert_manager()
        
        peak_score = summary["peak_risk"]
        alert_lvl_str = recommendation.alert_level.value
        
        if alert_lvl_str != "SAFE":
            from backend.threats.models import (
                ThreatEvent, Evidence, Explanation, ThreatCategory, RiskLevel
            )
            
            evidences = [
                Evidence(
                    evidence_type="voice_clone_probability",
                    description=(
                        f"Uploaded audio analysis of '{file.filename}' processed {len(chunks)} speech segments. "
                        f"Peak synthetic probability: {peak_score:.3f}, mean: {summary['mean_risk']:.3f}."
                    ),
                    value=f"peak={peak_score:.3f}",
                    severity_contribution=peak_score,
                    confidence=0.9,
                    source="VoiceCloneDetector"
                )
            ]
            if vt_result and vt_result.get("status") == "COMPLETED":
                mal = vt_result.get("malicious_count", 0)
                tot = vt_result.get("total_engines", 0)
                if mal > 0:
                    evidences.append(Evidence(
                        evidence_type="vt_file_hash_match",
                        description=f"VirusTotal reported {mal}/{tot} security engines flagged file SHA-256 hash as malicious.",
                        value=file_hash_hex,
                        severity_contribution=min(1.0, mal * 0.1),
                        source="VirusTotal"
                    ))

            threat_event = ThreatEvent(
                source=f"File: {file.filename or 'upload'}",
                source_type="audio_file",
                modality="audio",
                threat_category=ThreatCategory.VOICE_CLONING if peak_score >= 0.35 else ThreatCategory.SAFE,
                severity=RiskLevel(alert_lvl_str),
                confidence=0.9,
                classification="MALICIOUS" if alert_lvl_str in ("HIGH", "CRITICAL") else ("SUSPICIOUS" if alert_lvl_str == "MEDIUM" else "SAFE"),
                evidence=evidences,
                explanation=Explanation(
                    summary=recommendation.title,
                    reasoning=recommendation.message,
                    limitations="Acoustic analysis based on calibrated multi-feature spectral and prosodic baselines."
                ),
                recommended_actions=recommendation.actions or [],
                affected_user=speaker_id,
                detector="VoiceCloneDetector",
                processing_time_ms=total_ms,
                correlation_id=session_id,
                mitre_technique_id="T1656",
                mitre_technique_name="Impersonation / Synthetic Voice Cloning",
                threat_intelligence=vt_result,
            )

            if inc_manager:
                try:
                    inc_manager.process_event(threat_event)
                except Exception as inc_err:
                    logger.warning(f"Failed to record threat event in incident manager: {inc_err}")

            if alert_mgr and alert_lvl_str in ("HIGH", "CRITICAL"):
                try:
                    asyncio.create_task(alert_mgr.dispatch(
                        session_id=session_id,
                        chunk_id=0,
                        risk_score=peak_score,
                        alert_level=recommendation.alert_level,
                        recommendation=recommendation,
                        detection_score=peak_score,
                        speaker_id=speaker_id,
                    ))
                except Exception as alert_err:
                    logger.warning(f"Failed to dispatch alert notification: {alert_err}")

        # ── Model Version & Continuous Learning Vault Storage ─────────────────
        active_version = "v001"
        if db:
            active_mv = (
                db.query(ModelVersionModel)
                .filter(ModelVersionModel.status == "ACTIVE")
                .order_by(ModelVersionModel.id.desc())
                .first()
            )
            if active_mv:
                active_version = active_mv.version

        # Secure non-public audio storage for review & training
        vault_rel_path: Optional[str] = None
        try:
            vault_dir = Path("data/audio_vault")
            vault_dir.mkdir(parents=True, exist_ok=True)
            vault_file = vault_dir / f"{file_hash_hex}.flac"
            if not vault_file.exists():
                import soundfile as sf
                sf.write(str(vault_file), audio[:320000], app_settings.audio.sample_rate)
            vault_rel_path = str(vault_file.as_posix())
        except Exception as v_err:
            logger.warning(f"Audio vault write notice: {v_err}")

        # Persist AnalysisRecord & enqueue into ReviewQueueItem
        if db:
            try:
                record = AnalysisRecordModel(
                    analysis_id=session_id,
                    user_id=current_user.id if current_user else None,
                    filename=file.filename or "unknown",
                    audio_hash=file_hash_hex,
                    audio_path=vault_rel_path,
                    duration_sec=float(len(audio) / app_settings.audio.sample_rate),
                    total_chunks=len(chunks),
                    detector_version=active_version,
                    native_probability=float(summary["peak_risk"]),
                    peak_risk=float(summary["peak_risk"]),
                    mean_risk=float(summary["mean_risk"]),
                    alert_level=recommendation.alert_level.value,
                    analysis_status="COMPLETED",
                )
                db.add(record)

                review_item = ReviewQueueModel(
                    review_id=f"REV_{session_id}",
                    analysis_id=session_id,
                    submitted_by_user_id=current_user.id if current_user else None,
                    status="PENDING",
                )
                db.add(review_item)
                db.commit()
            except Exception as db_err:
                db.rollback()
                logger.warning(f"Failed to record analysis to database: {db_err}")

        return AnalysisResponse(
            session_id=session_id,
            filename=file.filename or "unknown",
            total_chunks=len(chunks),
            peak_risk=summary["peak_risk"],
            mean_risk=summary["mean_risk"],
            final_risk=final_risk,
            alert_level=recommendation.alert_level.value,
            recommendation={
                "title": recommendation.title,
                "message": recommendation.message,
                "actions": recommendation.actions,
                "color": recommendation.color,
            },
            chunk_scores=chunk_scores,
            processing_time_ms=total_ms,
            detector_version=active_version,
            external_intelligence=vt_result
        )

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(f"Analysis failed: {exc}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")
    finally:
        # Privacy: always delete temp file, regardless of success or failure
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError as e:
                logger.warning(f"Failed to delete analysis temp file {tmp_path}: {e}")


@router.get("/history/me")
async def get_my_analysis_history(
    limit: int = 50,
    current_user: UserModel = Depends(require_user),
    db: Session = Depends(get_db_session),
):
    """Retrieve the authenticated user's own scan history. Cannot see other users' scans."""
    records = (
        db.query(AnalysisRecordModel)
        .filter(AnalysisRecordModel.user_id == current_user.id)
        .order_by(AnalysisRecordModel.id.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "analysis_id": r.analysis_id,
            "filename": r.filename,
            "duration_sec": r.duration_sec,
            "total_chunks": r.total_chunks,
            "detector_version": r.detector_version,
            "native_probability": r.native_probability,
            "peak_risk": r.peak_risk,
            "alert_level": r.alert_level,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]
