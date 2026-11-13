"""
image_forensics.py — Digital Signal Processing & Traditional Image Forensic Engine.

Core Forensic Methods:
  1. Error Level Analysis (ELA) with spatial grid disparity and localization heatmap generation.
  2. 2D FFT Frequency Analysis with Hann windowing, high-frequency attenuation, and off-axis periodic lattice peak detection.
  3. Native-Resolution Noise Residual & PRNU Kurtosis with structural edge-masking and multi-quadrant disparity.
  4. Resampling & Interpolation Analysis (derivative periodicity and normalized Laplacian edge variance).
  5. Facial Region Forensics (Haar cascade detection, boundary seam ratio, waxy microtexture, eye asymmetry).
  6. Inter-Channel Color Gradient Correlation (optical lens dispersion).
  7. Suspicious Region Localization (bounding boxes + Base64 visual heatmap).
"""

from __future__ import annotations

import base64
import io
import logging
import os
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
from PIL import Image
import scipy.ndimage
import scipy.signal

from backend.config import get_settings, ImageForensicsConfig
from backend.threats.models import Evidence

logger = logging.getLogger(__name__)


class ImageForensicsEngine:
    """Multi-signal DSP forensic inspection and localization engine."""

    def __init__(self, config: Optional[ImageForensicsConfig] = None):
        if config is None:
            settings = get_settings()
            config = getattr(settings, "image_forensics", None) or ImageForensicsConfig()
        self.config = config

    def analyze_image_bytes(self, media_bytes: bytes, filename: str = "image.jpg"):
        """Convenience method to inspect image bytes directly."""
        img = Image.open(io.BytesIO(media_bytes))
        metrics, evidences, prob = self.analyze(img)

        class ImageAnalysisResult:
            def __init__(self, m, e, p):
                self.metrics = m
                self.evidences = e
                self.manipulation_probability = p
                self.ela_heatmap_base64 = m.get("ela_heatmap_base64")

        return ImageAnalysisResult(metrics, evidences, prob)

    def compare_with_reference(self, image: Image.Image, reference: Image.Image) -> Dict[str, Any]:
        """
        Align an analyst-supplied reference image and localize material visual differences.

        A difference is not automatically an edit: motion, lighting, viewpoint changes,
        resampling, and other capture differences can also produce changed regions.
        """
        import cv2
        from PIL import ImageOps

        cfg = self.config
        target_oriented = ImageOps.exif_transpose(image)
        reference_oriented = ImageOps.exif_transpose(reference)
        target_size = target_oriented.size
        reference_size = reference_oriented.size

        def _resize_for_analysis(pil_image: Image.Image):
            width, height = pil_image.size
            limit = max(64, int(getattr(cfg, "reference_max_dimension", 1600)))
            scale = min(1.0, limit / float(max(width, height)))
            if scale < 1.0:
                size = (max(1, int(round(width * scale))), max(1, int(round(height * scale))))
                pil_image = pil_image.resize(size, Image.Resampling.LANCZOS)
            # Convert to RGB only after resizing to avoid a second full-resolution color array.
            return np.asarray(pil_image.convert("RGB"), dtype=np.uint8), scale

        target_array, _target_scale = _resize_for_analysis(target_oriented)
        reference_array, reference_scale = _resize_for_analysis(reference_oriented)
        target_gray = cv2.cvtColor(target_array, cv2.COLOR_RGB2GRAY)
        reference_gray = cv2.cvtColor(reference_array, cv2.COLOR_RGB2GRAY)

        def _not_comparable(reason: str, **details: Any) -> Dict[str, Any]:
            return {
                "status": "NOT_COMPARABLE",
                "difference_detected": False,
                "reason": reason,
                "target_dimensions": [int(target_size[0]), int(target_size[1])],
                "reference_dimensions": [int(reference_size[0]), int(reference_size[1])],
                "alignment": details,
                "interpretation": "A failed comparison is not evidence that the image is unmodified.",
            }

        orb = cv2.ORB_create(
            nfeatures=max(500, int(getattr(cfg, "reference_max_features", 4000))),
            scaleFactor=1.2,
            nlevels=8,
            edgeThreshold=15,
            fastThreshold=10,
        )
        target_keypoints, target_descriptors = orb.detectAndCompute(target_gray, None)
        reference_keypoints, reference_descriptors = orb.detectAndCompute(reference_gray, None)
        if target_descriptors is None or reference_descriptors is None:
            return _not_comparable("Insufficient visual features for reliable registration.")

        matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
        try:
            candidate_matches = matcher.knnMatch(target_descriptors, reference_descriptors, k=2)
        except cv2.error as exc:
            return _not_comparable(f"Feature matching failed: {exc}")

        match_ratio = float(getattr(cfg, "reference_match_ratio", 0.75))
        good_matches = [
            first
            for pair in candidate_matches if len(pair) == 2
            for first, second in [pair]
            if first.distance < match_ratio * second.distance
        ]
        min_inliers = int(getattr(cfg, "reference_min_inliers", 20))
        if len(good_matches) < min_inliers:
            return _not_comparable(
                "Too few reliable feature matches to establish that the images show the same scene.",
                feature_matches=len(good_matches),
            )

        source_points = np.float32(
            [target_keypoints[match.queryIdx].pt for match in good_matches]
        ).reshape(-1, 1, 2)
        destination_points = np.float32(
            [reference_keypoints[match.trainIdx].pt for match in good_matches]
        ).reshape(-1, 1, 2)
        try:
            homography, inlier_mask = cv2.findHomography(
                source_points,
                destination_points,
                cv2.RANSAC,
                float(getattr(cfg, "reference_ransac_reprojection_px", 3.0)),
                maxIters=2000,
                confidence=0.995,
            )
        except cv2.error as exc:
            return _not_comparable(f"Geometric registration failed: {exc}", feature_matches=len(good_matches))

        if homography is None or inlier_mask is None or not np.isfinite(homography).all():
            return _not_comparable("The images could not be geometrically aligned.", feature_matches=len(good_matches))

        inliers = int(inlier_mask.sum())
        inlier_ratio = float(inliers / max(1, len(good_matches)))
        min_inlier_ratio = float(getattr(cfg, "reference_min_inlier_ratio", 0.25))
        if inliers < min_inliers or inlier_ratio < min_inlier_ratio:
            return _not_comparable(
                "Geometric registration quality fell below the reliability threshold.",
                feature_matches=len(good_matches),
                inliers=inliers,
                inlier_ratio=round(inlier_ratio, 4),
            )

        reference_height, reference_width = reference_array.shape[:2]
        try:
            aligned_target = cv2.warpPerspective(
                target_array,
                homography,
                (reference_width, reference_height),
                flags=cv2.INTER_LINEAR,
                borderMode=cv2.BORDER_CONSTANT,
                borderValue=0,
            )
        except cv2.error as exc:
            return _not_comparable(f"Perspective warp failed: {exc}", inliers=inliers, inlier_ratio=round(inlier_ratio, 4))

        target_presence_mask = cv2.warpPerspective(
            np.ones((target_array.shape[0], target_array.shape[1]), dtype=np.uint8) * 255,
            homography,
            (reference_width, reference_height),
            flags=cv2.INTER_NEAREST,
            borderMode=cv2.BORDER_CONSTANT,
            borderValue=0,
        )
        valid_pixels = target_presence_mask > 200
        coverage_ratio = float(valid_pixels.sum() / float(reference_width * reference_height))
        if coverage_ratio < 0.20:
            return _not_comparable(
                "Warped overlap area is too small to establish meaningful scene comparison.",
                inliers=inliers,
                inlier_ratio=round(inlier_ratio, 4),
                projected_coverage_ratio=round(coverage_ratio, 4),
            )

        target_lab = cv2.cvtColor(aligned_target, cv2.COLOR_RGB2LAB).astype(np.float32)
        reference_lab = cv2.cvtColor(reference_array, cv2.COLOR_RGB2LAB).astype(np.float32)
        lab_distance = np.sqrt(np.sum((target_lab - reference_lab) ** 2, axis=2))

        baseline = lab_distance[valid_pixels]
        if baseline.size == 0:
            return _not_comparable("No overlapping pixels available for difference calculation.")

        baseline_median = float(np.median(baseline))
        baseline_mad = float(np.median(np.abs(baseline - baseline_median)))
        adaptive_floor = baseline_median + (
            float(getattr(cfg, "reference_diff_mad_multiplier", 3.0)) * 1.4826 * baseline_mad
        )
        decision_threshold = max(float(getattr(cfg, "reference_diff_min_lab_distance", 7.0)), adaptive_floor)
        difference_mask = ((lab_distance > decision_threshold) & valid_pixels).astype(np.uint8)

        kernel_size = max(3, int(getattr(cfg, "reference_morphology_kernel", 7)))
        if kernel_size % 2 == 0:
            kernel_size += 1
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (kernel_size, kernel_size))
        difference_mask = cv2.morphologyEx(difference_mask, cv2.MORPH_CLOSE, kernel)
        difference_mask = cv2.morphologyEx(
            difference_mask,
            cv2.MORPH_OPEN,
            cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3)),
        )
        difference_mask = (difference_mask > 0).astype(np.uint8)

        component_count, component_labels, component_stats, _ = cv2.connectedComponentsWithStats(
            difference_mask, connectivity=8
        )
        valid_area = max(1, int(valid_pixels.sum()))
        regions = []
        min_comp_area = int(getattr(cfg, "reference_min_component_area", 64))
        min_area_ratio = float(getattr(cfg, "reference_min_changed_area_ratio", 0.001))
        for component_index in range(1, component_count):
            x, y, width, height, area = [int(value) for value in component_stats[component_index]]
            area_ratio = float(area / valid_area)
            if area < min_comp_area or area_ratio < min_area_ratio:
                continue
            region_mask = component_labels == component_index
            mean_distance = float(np.mean(lab_distance[region_mask]))
            regions.append({
                "bbox": [
                    int(round(x / reference_scale)),
                    int(round(y / reference_scale)),
                    int(round(width / reference_scale)),
                    int(round(height / reference_scale)),
                ],
                "area_pixels": int(round(area / (reference_scale ** 2))),
                "area_ratio": round(area_ratio, 6),
                "mean_lab_distance": round(mean_distance, 3),
            })
        regions.sort(key=lambda region: region["area_pixels"], reverse=True)
        regions = regions[:25]

        changed_pixels = int(difference_mask.sum())
        changed_ratio = float(changed_pixels / valid_area)
        difference_detected = bool(regions)
        heatmap_scale = max(float(np.percentile(baseline, 99.5)) - decision_threshold, 1.0)
        heatmap = cv2.applyColorMap(
            np.clip((lab_distance - decision_threshold) * (255.0 / heatmap_scale), 0, 255).astype(np.uint8),
            cv2.COLORMAP_TURBO,
        )
        reference_bgr = cv2.cvtColor(reference_array, cv2.COLOR_RGB2BGR)
        overlay = cv2.addWeighted(reference_bgr, 0.58, heatmap, 0.42, 0.0)
        overlay[~valid_pixels] = reference_bgr[~valid_pixels]
        encoded_ok, encoded_heatmap = cv2.imencode(
            ".jpg", overlay, [cv2.IMWRITE_JPEG_QUALITY, 82]
        )
        heatmap_base64 = (
            base64.b64encode(encoded_heatmap.tobytes()).decode("ascii")
            if encoded_ok else None
        )

        return {
            "status": "COMPARABLE",
            "difference_detected": difference_detected,
            "difference_type": "MATERIAL_REFERENCE_DIFFERENCES" if difference_detected else "NO_SIGNIFICANT_DIFFERENCE_DETECTED",
            "changed_pixel_ratio": round(changed_ratio, 6),
            "changed_pixel_percent": round(changed_ratio * 100.0, 3),
            "component_count": len(regions),
            "largest_region": regions[0] if regions else None,
            "regions": regions,
            "difference_threshold_lab_distance": round(decision_threshold, 3),
            "baseline_lab_distance_median": round(baseline_median, 3),
            "baseline_lab_distance_mad": round(baseline_mad, 3),
            "difference_heatmap_base64": heatmap_base64,
            "target_dimensions": [int(target_size[0]), int(target_size[1])],
            "reference_dimensions": [int(reference_size[0]), int(reference_size[1])],
            "alignment": {
                "method": "ORB_FEATURES_RANSAC_HOMOGRAPHY",
                "feature_matches": len(good_matches),
                "inliers": inliers,
                "inlier_ratio": round(inlier_ratio, 4),
                "projected_coverage_ratio": round(coverage_ratio, 4),
            },
            "interpretation": (
                "Material pixel differences are localized relative to the supplied reference. "
                "They may result from object movement, lighting, capture changes, retouching, or removal; "
                "this comparison does not by itself establish AI generation or the cause of the changes."
            ),
        }

    def analyze(self, img: Image.Image) -> Tuple[Dict[str, Any], List[Evidence], float]:
        """
        Execute full multi-domain forensic inspection.
        Returns:
          - forensic_metrics: Detailed dictionary including metrics, bounding boxes, and base64 heatmap
          - evidences: List of standardized Evidence objects
          - combined_signal_prob: Calibrated manipulation probability
        """
        evidences: List[Evidence] = []
        domain_anomalies: List[float] = []

        # ── 1. Error Level Analysis (ELA) & Suspicious Region Heatmap ─────────────
        rgb_img = img.convert("RGB")
        w, h = rgb_img.size
        sample_img = rgb_img
        if max(w, h) > 1024:
            scale = 1024.0 / max(w, h)
            sample_img = rgb_img.resize((int(w * scale), int(h * scale)), Image.Resampling.BILINEAR)

        buf = io.BytesIO()
        sample_img.save(buf, format="JPEG", quality=self.config.ela_quality)
        buf.seek(0)
        recomp = Image.open(buf)

        arr_orig = np.array(sample_img, dtype=np.float32)
        arr_recomp = np.array(recomp, dtype=np.float32)
        diff = np.abs(arr_orig - arr_recomp)

        ela_mean = float(np.mean(diff))
        ela_max = float(np.max(diff))
        ela_std = float(np.std(diff))

        # Check spatial block disparity (4x4 grid across image)
        bh, bw = diff.shape[0] // 4, diff.shape[1] // 4
        block_means = []
        suspicious_blocks = []
        if bh >= 4 and bw >= 4:
            for r in range(4):
                for c in range(4):
                    block = diff[r * bh:(r + 1) * bh, c * bw:(c + 1) * bw]
                    b_mean = float(np.mean(block))
                    block_means.append(b_mean)
                    if b_mean > (ela_mean + 1.8 * (ela_std + 1e-4)):
                        suspicious_blocks.append({
                            "row": r,
                            "col": c,
                            "box": [round(r * 0.25, 2), round(c * 0.25, 2), round((r + 1) * 0.25, 2), round((c + 1) * 0.25, 2)],
                            "error_mean": round(b_mean, 2),
                        })
            ela_disparity = float(np.std(block_means))
        else:
            ela_disparity = 0.0

        # Generate a false-color visual heatmap of compression error for SOC analyst inspection
        heatmap_base64 = self._generate_ela_heatmap(diff)

        s_ela = 0.0
        ela_status = "NOMINAL"
        if ela_disparity >= self.config.ela_disparity_critical and ela_max > self.config.ela_max_diff_threshold:
            s_ela = 0.35
            ela_status = "CRITICAL"
            evidences.append(Evidence(
                evidence_type="ela_localized_disparity",
                description=f"Error Level Analysis (ELA) reveals significant localized compression variance ({ela_disparity:.2f} disparity, max: {ela_max:.1f}), consistent with digital splicing or localized inpainting.",
                value=f"disparity={ela_disparity:.2f}",
                severity_contribution=0.35,
                source="HeuristicForensics",
            ))
        elif ela_disparity >= self.config.ela_disparity_moderate:
            s_ela = 0.20
            ela_status = "MODERATE"
            evidences.append(Evidence(
                evidence_type="ela_mild_disparity",
                description=f"Moderate spatial compression disparity observed ({ela_disparity:.2f}).",
                value=f"disparity={ela_disparity:.2f}",
                severity_contribution=0.20,
                source="HeuristicForensics",
            ))
        elif ela_mean < self.config.ela_nominal_max:
            evidences.append(Evidence(
                evidence_type="ela_compression_nominal",
                description=f"Error Level Analysis confirms uniform compression response across spatial zones (mean: {ela_mean:.2f}).",
                value=f"mean={ela_mean:.2f}",
                severity_contribution=0.0,
                source="HeuristicForensics",
            ))
        domain_anomalies.append(s_ela)

        # ── 2. Calibrated 2D FFT Frequency Domain Analysis ───────────────────────
        gray = img.convert("L").resize((256, 256), Image.Resampling.BILINEAR)
        arr_256 = np.array(gray, dtype=np.float32)
        hann_2d = np.outer(np.hanning(256), np.hanning(256))
        windowed = (arr_256 - np.mean(arr_256)) * hann_2d

        f_shift = np.fft.fftshift(np.fft.fft2(windowed))
        magnitude = np.abs(f_shift)

        center_x, center_y = 128, 128
        y_idx, x_idx = np.ogrid[:256, :256]
        dist = np.sqrt((x_idx - center_x) ** 2 + (y_idx - center_y) ** 2)

        high_mask = (dist > 64) & (dist <= 120)
        low_mask = (dist > 4) & (dist <= 32)
        high_energy = float(np.mean(magnitude[high_mask]))
        low_energy = float(np.mean(magnitude[low_mask])) + 1e-6
        energy_ratio = float(high_energy / low_energy)

        # Off-axis periodic harmonic lattice detection (transposed convolution spikes)
        cardinal_axes = (np.abs(x_idx - 128) <= 3) | (np.abs(y_idx - 128) <= 3)
        dct_8x8_axes = (
            (np.abs(np.abs(x_idx - 128) - 32) <= 1) | (np.abs(np.abs(y_idx - 128) - 32) <= 1) |
            (np.abs(np.abs(x_idx - 128) - 64) <= 1) | (np.abs(np.abs(y_idx - 128) - 64) <= 1) |
            (np.abs(np.abs(x_idx - 128) - 96) <= 1) | (np.abs(np.abs(y_idx - 128) - 96) <= 1)
        )
        off_axis_mask = high_mask & (~cardinal_axes) & (~dct_8x8_axes)

        med_spectrum = scipy.ndimage.median_filter(magnitude, size=7)
        diff_spectrum = (magnitude - med_spectrum) / (med_spectrum + 1e-5)
        off_axis_spikes = diff_spectrum[off_axis_mask] if np.any(off_axis_mask) else np.array([0.0])
        off_axis_max_spike = float(np.max(off_axis_spikes)) if len(off_axis_spikes) > 0 else 0.0
        p99_spike = float(np.percentile(off_axis_spikes, 99.5)) if len(off_axis_spikes) > 0 else 0.0
        critical_spike_count = int(np.sum(off_axis_spikes >= self.config.fft_lattice_spike_critical))
        moderate_spike_count = int(np.sum(off_axis_spikes >= self.config.fft_lattice_spike_moderate))

        p99 = float(np.percentile(magnitude[high_mask], 99.8))
        med_hi = float(np.median(magnitude[high_mask])) + 1e-6
        peak_to_median = float(p99 / med_hi)

        s_freq = 0.0
        is_compact_asset = min(w, h) < 128
        if is_compact_asset:
            # Low-resolution assets cannot be reliably evaluated for high-frequency latent diffusion
            # or transposed-convolution upsampling via 256x256 bilinear interpolation,
            # which naturally attenuates frequencies beyond the native Nyquist limit.
            evidences.append(Evidence(
                evidence_type="spectral_compact_resolution_baseline",
                description=f"2D FFT frequency spectrum evaluated across native compact asset ({w}x{h}). High-frequency roll-off reflects physical resolution boundaries rather than latent diffusion upsampling.",
                value=f"hf_ratio={energy_ratio:.4f}",
                severity_contribution=0.0,
                source="HeuristicForensics",
            ))
            fft_status = "NOMINAL"
            s_freq = 0.0
        else:
            if off_axis_max_spike >= self.config.fft_lattice_spike_critical and (critical_spike_count >= 2 or p99_spike >= 2.5):
                s_freq = max(s_freq, 0.45)
                evidences.append(Evidence(
                    evidence_type="spectral_periodic_lattice",
                    description=f"2D FFT frequency spectrum reveals prominent periodic lattice spikes ({off_axis_max_spike:.2f}x background), indicative of neural transposed-convolution upsampling artifacts.",
                    value=f"spike_ratio={off_axis_max_spike:.2f}",
                    severity_contribution=0.45,
                    source="HeuristicForensics",
                ))
            elif moderate_spike_count >= self.config.fft_lattice_min_peaks and off_axis_max_spike >= self.config.fft_lattice_spike_moderate:
                s_freq = max(s_freq, 0.20)
                evidences.append(Evidence(
                    evidence_type="mild_spectral_harmonics",
                    description=f"Periodic frequency harmonics observed in 2D spectrum ({off_axis_max_spike:.2f}x background, {moderate_spike_count} harmonic peaks).",
                    value=f"spike_ratio={off_axis_max_spike:.2f}",
                    severity_contribution=0.20,
                    source="HeuristicForensics",
                ))

            is_large_natural = max(w, h) >= 800
            if energy_ratio < self.config.fft_high_freq_attenuation_critical:
                if not is_large_natural:
                    s_freq = max(s_freq, 0.45)
                    evidences.append(Evidence(
                        evidence_type="spectral_high_freq_attenuation",
                        description=f"Severe high-frequency attenuation in Fourier spectrum (HF ratio: {energy_ratio:.4f}), consistent with neural latent diffusion upsampling without optical sensor detail.",
                        value=f"hf_ratio={energy_ratio:.4f}",
                        severity_contribution=0.45,
                        source="HeuristicForensics",
                    ))
                else:
                    s_freq = max(s_freq, 0.20)
                    evidences.append(Evidence(
                        evidence_type="spectral_high_freq_attenuation",
                        description=f"High-frequency attenuation in Fourier spectrum (HF ratio: {energy_ratio:.4f}).",
                        value=f"hf_ratio={energy_ratio:.4f}",
                        severity_contribution=0.20,
                        source="HeuristicForensics",
                    ))
            elif energy_ratio < self.config.fft_high_freq_attenuation_moderate:
                if not is_large_natural:
                    s_freq = max(s_freq, 0.20)
                    evidences.append(Evidence(
                        evidence_type="spectral_high_freq_attenuation",
                        description=f"Moderate high-frequency attenuation in Fourier spectrum (HF ratio: {energy_ratio:.4f}).",
                        value=f"hf_ratio={energy_ratio:.4f}",
                        severity_contribution=0.20,
                        source="HeuristicForensics",
                    ))
            elif energy_ratio > self.config.fft_high_freq_boost_threshold:
                s_freq = max(s_freq, 0.25)
                evidences.append(Evidence(
                    evidence_type="spectral_high_freq_boost",
                    description=f"Anomalous high-frequency energy concentration (HF ratio: {energy_ratio:.4f}), indicative of synthetic checkerboard noise or artificial post-processing.",
                    value=f"hf_ratio={energy_ratio:.4f}",
                    severity_contribution=0.25,
                    source="HeuristicForensics",
                ))

            if s_freq == 0.0:
                evidences.append(Evidence(
                    evidence_type="spectral_distribution_natural",
                    description="2D FFT radial energy demonstrates smooth natural power-law drop-off without synthetic grid spikes.",
                    value=f"high_low_ratio={energy_ratio:.4f}",
                    severity_contribution=0.0,
                    source="HeuristicForensics",
                ))
            fft_status = "CRITICAL" if s_freq >= 0.40 else ("MODERATE" if s_freq >= 0.20 else "NOMINAL")
        domain_anomalies.append(s_freq)

        # ── 3. Native-Resolution Multi-Region Noise Residual & PRNU Kurtosis ────
        native_gray = np.array(img.convert("L"), dtype=np.float32)
        orig_h, orig_w = native_gray.shape

        crop_size = min(self.config.noise_crop_size, orig_h, orig_w)
        # Sample up to 5 spatial patches across the image: center + 4 quadrants
        coords = [((orig_h - crop_size) // 2, (orig_w - crop_size) // 2)]
        if orig_h >= int(crop_size * 1.5) and orig_w >= int(crop_size * 1.5):
            coords.extend([
                (int(orig_h * 0.1), int(orig_w * 0.1)),
                (int(orig_h * 0.1), max(0, int(orig_w * 0.9) - crop_size)),
                (max(0, int(orig_h * 0.9) - crop_size), int(orig_w * 0.1)),
                (max(0, int(orig_h * 0.9) - crop_size), max(0, int(orig_w * 0.9) - crop_size)),
            ])

        patch_vars = []
        patch_kurts = []
        for py, px in coords:
            py = max(0, min(orig_h - crop_size, py))
            px = max(0, min(orig_w - crop_size, px))
            patch = native_gray[py:py + crop_size, px:px + crop_size]
            denoised = scipy.ndimage.median_filter(patch, size=3)
            res = patch - denoised

            gx = scipy.ndimage.sobel(patch, axis=1)
            gy = scipy.ndimage.sobel(patch, axis=0)
            gmag = np.hypot(gx, gy)
            edge_thresh = np.percentile(gmag, self.config.noise_edge_mask_percentile)
            flat_mask = gmag <= edge_thresh

            if np.any(flat_mask) and np.sum(flat_mask) >= 64:
                res_eval = res[flat_mask]
            else:
                res_eval = res

            v = float(np.var(res_eval))
            k = float(np.mean(res_eval ** 4) / ((v + 1e-6) ** 2))
            patch_vars.append(v)
            patch_kurts.append(k)

        res_var = float(np.median(patch_vars)) if patch_vars else 0.0
        kurtosis = float(np.median(patch_kurts)) if patch_kurts else 3.0

        # Disparity across patches (or within center patch quadrants if single patch)
        if len(patch_vars) > 1:
            quadrant_noise_disparity = float(np.std(patch_vars) / (np.mean(patch_vars) + 1e-5))
        else:
            center_patch = native_gray[(orig_h - crop_size) // 2:(orig_h - crop_size) // 2 + crop_size, (orig_w - crop_size) // 2:(orig_w - crop_size) // 2 + crop_size]
            c_den = scipy.ndimage.median_filter(center_patch, size=3)
            c_res = center_patch - c_den
            qh, qw = center_patch.shape[0] // 2, center_patch.shape[1] // 2
            q_vars = [float(np.var(c_res[qr * qh:(qr + 1) * qh, qc * qw:(qc + 1) * qw])) for qr in range(2) for qc in range(2)]
            quadrant_noise_disparity = float(np.std(q_vars) / (np.mean(q_vars) + 1e-5))

        s_noise = 0.0
        noise_status = "NOMINAL"
        noise_substatus = "NOMINAL_GAUSSIAN"
        excess_kurt = float(kurtosis - 3.0)
        is_compact_asset = min(orig_h, orig_w) < 128

        if res_var < self.config.noise_variance_flattened:
            s_noise = 0.45
            noise_status = "CRITICAL"
            noise_substatus = "NOISE_FLATTENED"
            evidences.append(Evidence(
                evidence_type="synthetic_noise_flattening",
                description=f"Severe sensor noise residual flattening (variance: {res_var:.3f}, kurtosis: {kurtosis:.1f}, excess: {excess_kurt:.1f}), characteristic of synthetic rendering or heavy diffusion denoising.",
                value=f"variance={res_var:.3f}",
                severity_contribution=0.45,
                source="HeuristicForensics",
            ))
        elif kurtosis >= self.config.noise_kurtosis_critical:
            s_noise = 0.45
            noise_status = "CRITICAL"
            noise_substatus = "HEAVY_TAIL"
            evidences.append(Evidence(
                evidence_type="synthetic_noise_kurtosis_anomaly",
                description=f"Extreme non-Gaussian noise residual kurtosis ({kurtosis:.1f}, excess: {excess_kurt:.1f}, variance: {res_var:.3f}), characteristic of latent diffusion denoising artifacts deviating from physical CMOS/CCD sensor shot noise.",
                value=f"kurtosis={kurtosis:.1f}",
                severity_contribution=0.45,
                source="HeuristicForensics",
            ))
        elif kurtosis >= self.config.noise_kurtosis_moderate:
            if is_compact_asset and res_var >= 1.0:
                s_noise = 0.0
                noise_status = "NOMINAL"
                noise_substatus = "COMPACT_EDGE_KURTOSIS"
                evidences.append(Evidence(
                    evidence_type="sensor_noise_compact_profile",
                    description=f"Sensor noise residual exhibits elevated kurtosis ({kurtosis:.1f}, excess: {excess_kurt:.1f}, variance: {res_var:.3f}) attributable to high edge density on compact ({orig_w}x{orig_h}) asset; non-Gaussian, but typical for compressed web portraits.",
                    value=f"kurtosis={kurtosis:.1f}",
                    severity_contribution=0.0,
                    source="HeuristicForensics",
                ))
            else:
                s_noise = 0.25
                noise_status = "MODERATE"
                noise_substatus = "ELEVATED_KURTOSIS"
                evidences.append(Evidence(
                    evidence_type="synthetic_noise_kurtosis_anomaly",
                    description=f"Elevated noise residual kurtosis ({kurtosis:.1f}, excess: {excess_kurt:.1f}, variance: {res_var:.3f}) deviating from natural camera sensor profile.",
                    value=f"kurtosis={kurtosis:.1f}",
                    severity_contribution=0.25,
                    source="HeuristicForensics",
                ))
        elif kurtosis >= self.config.noise_kurtosis_mild:
            if is_compact_asset or res_var >= 5.0:
                s_noise = 0.0
                noise_status = "NOMINAL"
                noise_substatus = "COMPACT_EDGE_KURTOSIS"
                evidences.append(Evidence(
                    evidence_type="sensor_noise_compact_profile",
                    description=f"Sensor noise residual exhibits elevated kurtosis ({kurtosis:.1f}, excess: {excess_kurt:.1f}, variance: {res_var:.3f}) attributable to high edge density on compact ({orig_w}x{orig_h}) asset; non-Gaussian, but consistent with natural compressed portrait.",
                    value=f"kurtosis={kurtosis:.1f}",
                    severity_contribution=0.0,
                    source="HeuristicForensics",
                ))
            else:
                s_noise = 0.15
                noise_status = "MODERATE"
                noise_substatus = "MILD_ANOMALY"
                evidences.append(Evidence(
                    evidence_type="mild_noise_anomaly",
                    description=f"Mild sensor noise residual anomaly observed (variance: {res_var:.3f}, kurtosis: {kurtosis:.1f}, excess: {excess_kurt:.1f}).",
                    value=f"kurtosis={kurtosis:.1f}",
                    severity_contribution=0.15,
                    source="HeuristicForensics",
                ))
        elif 2.0 <= kurtosis <= 6.0:
            s_noise = 0.0
            noise_status = "NOMINAL"
            noise_substatus = "NOMINAL_GAUSSIAN"
            evidences.append(Evidence(
                evidence_type="sensor_noise_nominal",
                description=f"Sensor noise residual exhibits natural Gaussian-consistent statistics (kurtosis: {kurtosis:.1f}, excess kurtosis: {excess_kurt:.1f}, variance: {res_var:.3f}).",
                value=f"kurtosis={kurtosis:.1f}",
                severity_contribution=0.0,
                source="HeuristicForensics",
            ))
        else:
            s_noise = 0.0
            noise_status = "NOMINAL"
            noise_substatus = "NOMINAL_SMOOTH"
            evidences.append(Evidence(
                evidence_type="sensor_noise_nominal",
                description=f"Sensor noise residual exhibits near-Gaussian statistics with mild tail divergence (kurtosis: {kurtosis:.1f}, excess kurtosis: {excess_kurt:.1f}, variance: {res_var:.3f}).",
                value=f"kurtosis={kurtosis:.1f}",
                severity_contribution=0.0,
                source="HeuristicForensics",
            ))

        if quadrant_noise_disparity > 1.4 and res_var >= 1.0:
            s_noise = max(s_noise, 0.25)
            evidences.append(Evidence(
                evidence_type="noise_quadrant_inconsistency",
                description=f"Significant spatial noise inconsistency detected across image quadrants (disparity ratio: {quadrant_noise_disparity:.2f}), consistent with multi-source compositing.",
                value=f"disparity={quadrant_noise_disparity:.2f}",
                severity_contribution=0.25,
                source="HeuristicForensics",
            ))
        domain_anomalies.append(s_noise)

        # ── 4. Normalized Edge Variance & Resampling Analysis ────────────────────
        edge_sub = native_gray[:512, :512] if (native_gray.shape[0] >= 512 and native_gray.shape[1] >= 512) else native_gray
        lap_kernel = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
        laplacian = scipy.signal.convolve2d(edge_sub, lap_kernel, mode="valid")
        lap_var = float(laplacian.var())
        scene_var = float(edge_sub.var()) + 1e-6
        norm_edge_var = float(lap_var / scene_var)

        # Resampling periodic derivative trace check
        d_x = np.diff(edge_sub, axis=1)
        d_xx = np.diff(d_x, axis=1)
        resampling_trace = float(np.mean(np.abs(d_xx))) / (float(np.mean(np.abs(d_x))) + 1e-5)

        # ── 5. Facial Forensics & Face-Swap Seam Detection ───────────────────────
        face_info = self._detect_faces_and_analyze(img)
        s_facial = 0.0
        if face_info["facial_forensics_applicable"]:
            s_facial = face_info.get("facial_anomaly_score", 0.0)
            if s_facial > 0.0:
                if face_info.get("facial_smoothing_detected"):
                    evidences.append(Evidence(
                        evidence_type="facial_microtexture_smoothing",
                        description=f"Facial skin micro-texture exhibits synthetic waxy smoothing (skin laplacian: {face_info.get('skin_lap_var', 0.0)}, face edge: {face_info.get('face_lap_var', 0.0)}), characteristic of generative face replacement or neural airbrushing.",
                        value=f"face_lap_var={face_info.get('face_lap_var', 0.0)}",
                        severity_contribution=0.30,
                        source="FacialForensics",
                    ))
                if face_info.get("boundary_seam_detected"):
                    evidences.append(Evidence(
                        evidence_type="facial_boundary_discontinuity",
                        description=f"Perimeter edge discontinuity detected along facial boundary mask (seam ratio: {face_info.get('seam_ratio', 0.0)}x), consistent with face-swap blending seams.",
                        value=f"seam_ratio={face_info.get('seam_ratio', 0.0)}",
                        severity_contribution=0.25,
                        source="FacialForensics",
                    ))
                if face_info.get("eye_disparity_detected"):
                    evidences.append(Evidence(
                        evidence_type="facial_eye_disparity",
                        description="Bilateral eye region specular catchlight or variance disparity observed across facial landmarks.",
                        value="eye_asymmetry",
                        severity_contribution=0.20,
                        source="FacialForensics",
                    ))
            else:
                evidences.append(Evidence(
                    evidence_type="facial_region_forensics",
                    description=face_info["status"],
                    value=f"faces={face_info['faces_detected']}",
                    severity_contribution=0.0,
                    source="FacialForensics",
                ))
        else:
            evidences.append(Evidence(
                evidence_type="facial_forensics_status",
                description=face_info["status"],
                value="not_applicable",
                severity_contribution=0.0,
                source="HeuristicForensics",
            ))
        facial_status_level = "CRITICAL" if s_facial >= 0.40 else ("MODERATE" if s_facial >= 0.20 else "NOMINAL")
        domain_anomalies.append(s_facial)

        # ── 6. Inter-Channel Color Gradient Correlation ─────────────────────────
        s_color = 0.0
        color_corr = 1.0
        if img.mode in ("RGB", "RGBA"):
            try:
                arr_rgb = np.array(img.convert("RGB"), dtype=np.float32)
                h_c, w_c = arr_rgb.shape[:2]
                if min(h_c, w_c) >= 24:
                    if max(h_c, w_c) > 512:
                        scale = 512.0 / max(h_c, w_c)
                        arr_rgb = np.array(img.convert("RGB").resize((int(w_c * scale), int(h_c * scale)), Image.Resampling.BILINEAR), dtype=np.float32)
                    r_grad = np.hypot(np.gradient(arr_rgb[:, :, 0], axis=0), np.gradient(arr_rgb[:, :, 0], axis=1))
                    g_grad = np.hypot(np.gradient(arr_rgb[:, :, 1], axis=0), np.gradient(arr_rgb[:, :, 1], axis=1))
                    b_grad = np.hypot(np.gradient(arr_rgb[:, :, 2], axis=0), np.gradient(arr_rgb[:, :, 2], axis=1))
                    r_std, g_std, b_std = float(np.std(r_grad)), float(np.std(g_grad)), float(np.std(b_grad))
                    if r_std > 1e-4 and g_std > 1e-4 and b_std > 1e-4:
                        rg_corr = float(np.corrcoef(r_grad.flatten(), g_grad.flatten())[0, 1])
                        gb_corr = float(np.corrcoef(g_grad.flatten(), b_grad.flatten())[0, 1])
                        color_corr = min(rg_corr, gb_corr)
                    if color_corr < self.config.color_decorrelation_critical:
                        s_color = 0.25
                        evidences.append(Evidence(
                            evidence_type="color_channel_decorrelation",
                            description=f"Significant inter-channel gradient decorrelation ({color_corr:.3f}) deviating from natural optical lens dispersion.",
                            value=f"corr={color_corr:.3f}",
                            severity_contribution=0.25,
                            source="HeuristicForensics",
                        ))
                    elif color_corr < self.config.color_decorrelation_moderate:
                        s_color = 0.15
                        evidences.append(Evidence(
                            evidence_type="color_channel_decorrelation",
                            description=f"Inter-channel gradient decorrelation ({color_corr:.3f}) deviating from natural optical lens dispersion.",
                            value=f"corr={color_corr:.3f}",
                            severity_contribution=0.15,
                            source="HeuristicForensics",
                        ))
            except Exception as color_err:
                logger.debug(f"Color gradient correlation notice: {color_err}")
        domain_anomalies.append(s_color)

        # ── 7. Check for embedded QR code payload ────────────────────────────────
        qr_detected = False
        qr_payload = ""
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            decoded_qr = pyzbar_decode(img)
            if decoded_qr:
                qr_detected = True
                qr_payload = decoded_qr[0].data.decode("utf-8", errors="ignore")
                evidences.append(Evidence(
                    evidence_type="embedded_qr_code",
                    description=f"Image contains an embedded QR code with payload: {qr_payload[:80]}",
                    value=qr_payload[:120],
                    severity_contribution=0.20,
                    source="QRScanner",
                ))
                domain_anomalies.append(0.20)
        except (ImportError, Exception):
            pass

        # ── 8. Multi-Scale Localized Manipulation Subsystem ─────────────────────
        localized_manipulation = self._detect_localized_manipulation(
            img=img,
            diff=diff,
            native_gray=native_gray,
            ela_disparity=ela_disparity,
            noise_disparity=quadrant_noise_disparity,
        )
        if localized_manipulation.get("detected"):
            s_loc = float(localized_manipulation.get("anomaly_score", 0.40))
            domain_anomalies.append(s_loc)
            evidences.append(Evidence(
                evidence_type="localized_manipulation_detected",
                description=(
                    f"Multi-scale localized manipulation inspection identified spatial compression and noise disparity "
                    f"({localized_manipulation.get('component_count', 0)} localized region(s)). Consistent with localized inpainting or splicing."
                ),
                value=f"score={s_loc:.2f}",
                severity_contribution=s_loc,
                source="LocalizedManipulationSubsystem",
            ))

        # Calculate combined multi-domain anomaly probability using Noisy-OR Bayesian fusion
        prob_product = 1.0
        for a in domain_anomalies:
            prob_product *= (1.0 - max(0.0, min(1.0, a)))
        combined_signal_prob = 1.0 - prob_product

        forensic_metrics = {
            "ela_mean": round(ela_mean, 2),
            "ela_max": round(ela_max, 2),
            "ela_disparity": round(ela_disparity, 2),
            "ela_status": ela_status,
            "ela_heatmap_base64": heatmap_base64,
            "suspicious_regions": suspicious_blocks,
            "localized_manipulation": localized_manipulation,
            "fft_high_freq_ratio": round(energy_ratio, 4),
            "fft_grid_peak_ratio": round(peak_to_median, 2),
            "fft_off_axis_spike_ratio": round(off_axis_max_spike, 2),
            "fft_status": fft_status,
            "edge_variance": round(lap_var, 2),
            "normalized_edge_variance": round(norm_edge_var, 4),
            "resampling_trace": round(resampling_trace, 3),
            "noise_variance": round(res_var, 3),
            "noise_kurtosis": round(kurtosis, 1),
            "noise_status": noise_status,
            "noise_substatus": noise_substatus,
            "noise_attribution_note": "Generic 3x3 median spatial residual. Sensor PRNU attribution unavailable (no camera reference database).",
            "noise_quadrant_disparity": round(quadrant_noise_disparity, 2),
            "color_channel_correlation": round(float(color_corr), 4),
            "faces_detected": face_info["faces_detected"],
            "facial_forensics_applicable": face_info["facial_forensics_applicable"],
            "face_detection_status": face_info.get("face_detection_status", "NO_FACE_DETECTED"),
            "face_detection_confidence": face_info.get("face_detection_confidence", 0.0),
            "facial_status": face_info["status"],
            "facial_status_level": facial_status_level,
            "face_bounding_boxes": face_info.get("face_boxes", []),
            "excess_kurtosis": round(float(kurtosis - 3.0), 1),
            "noise_excess_kurtosis": round(float(kurtosis - 3.0), 1),
            "original_dimensions": [w, h],
            "fft_analysis_dimensions": [256, 256],
            "ela_analysis_dimensions": [sample_img.size[0], sample_img.size[1]],
            "qr_detected": qr_detected,
            "engine_type": "Heuristic Multi-Signal DSP & Forensics",
            "thresholds": {
                "manipulated": self.config.threshold_manipulated,
                "inconclusive": self.config.threshold_inconclusive,
                "critical": self.config.threshold_critical,
            },
        }

        return forensic_metrics, evidences, float(combined_signal_prob)

    def _detect_localized_manipulation(
        self,
        img: Image.Image,
        diff: np.ndarray,
        native_gray: np.ndarray,
        ela_disparity: float,
        noise_disparity: float,
    ) -> Dict[str, Any]:
        """
        Multi-scale localized manipulation inspection for single images.
        Detects localized inpainting, texture anomalies, and regional noise inconsistencies.
        """
        import cv2

        h_diff, w_diff = diff.shape[:2]
        diff_mag = np.mean(diff, axis=2) if diff.ndim == 3 else diff

        # Multi-scale 8x8 spatial grid
        gh, gw = 8, 8
        bh, bw = max(1, h_diff // gh), max(1, w_diff // gw)
        block_means = []
        suspicious_regions = []

        diff_med = float(np.median(diff_mag))
        diff_mad = float(np.median(np.abs(diff_mag - diff_med))) + 1e-5
        adaptive_thresh = diff_med + 3.0 * 1.4826 * diff_mad

        for r in range(gh):
            for c in range(gw):
                block = diff_mag[r * bh : (r + 1) * bh, c * bw : (c + 1) * bw]
                b_mean = float(np.mean(block))
                block_means.append(b_mean)
                if b_mean > adaptive_thresh and b_mean > 5.0:
                    suspicious_regions.append({
                        "grid": [r, c],
                        "bbox": [
                            int(c * bw),
                            int(r * bh),
                            int(bw),
                            int(bh),
                        ],
                        "normalized_box": [
                            round(r / float(gh), 3),
                            round(c / float(gw), 3),
                            round((r + 1) / float(gh), 3),
                            round((c + 1) / float(gw), 3),
                        ],
                        "score": round(min(1.0, (b_mean - diff_med) / (adaptive_thresh + 1e-5)), 2),
                        "type": "COMPRESSION_DISPARITY",
                    })

        ela_dense_disp = float(np.std(block_means)) if block_means else 0.0

        # Dense noise residual disparity
        h_nat, w_nat = native_gray.shape
        nth, ntw = max(8, h_nat // gh), max(8, w_nat // gw)
        tile_vars = []
        for r in range(gh):
            for c in range(gw):
                patch = native_gray[r * nth : (r + 1) * nth, c * ntw : (c + 1) * ntw]
                if patch.size < 64:
                    continue
                denoised = cv2.medianBlur(patch.astype(np.uint8), 3).astype(np.float32)
                res = patch - denoised
                # Sobel edge exclusion
                gx = cv2.Sobel(patch, cv2.CV_32F, 1, 0, ksize=3)
                gy = cv2.Sobel(patch, cv2.CV_32F, 0, 1, ksize=3)
                gmag = np.hypot(gx, gy)
                flat_mask = gmag <= np.percentile(gmag, 80)
                eval_res = res[flat_mask] if np.sum(flat_mask) >= 32 else res
                tile_vars.append(float(np.var(eval_res)))

        tile_var_arr = np.array(tile_vars, dtype=np.float32) if tile_vars else np.array([1.0], dtype=np.float32)
        dense_noise_disparity = float(np.std(tile_var_arr) / (np.mean(tile_var_arr) + 1e-5))

        has_critical_ela = ela_disparity >= float(self.config.ela_disparity_critical)
        has_dense_ela_anomaly = ela_dense_disp >= float(self.config.ela_disparity_critical)
        has_noise_disparity = noise_disparity > 1.4 or dense_noise_disparity > 2.2
        regions_detected = len(suspicious_regions) > 0

        if (has_critical_ela or has_dense_ela_anomaly) and has_noise_disparity:
            status = "EVIDENCE_DETECTED"
            detected = True
            anomaly_score = 0.75
        elif has_critical_ela or (regions_detected and has_noise_disparity):
            status = "EVIDENCE_DETECTED"
            detected = True
            anomaly_score = 0.65
        elif (ela_disparity >= float(self.config.ela_disparity_moderate)) or regions_detected or (dense_noise_disparity > 1.6):
            status = "INCONCLUSIVE"
            detected = False
            anomaly_score = 0.35
        else:
            status = "NO_EVIDENCE_DETECTED"
            detected = False
            anomaly_score = 0.0

        return {
            "status": status,
            "detected": detected,
            "anomaly_score": round(anomaly_score, 2),
            "regions": suspicious_regions[:12],
            "component_count": len(suspicious_regions),
            "dense_ela_disparity": round(ela_dense_disp, 3),
            "dense_noise_disparity": round(dense_noise_disparity, 3),
            "neural_inpainting_localization": "NOT_CONFIGURED",
            "scope": "SINGLE_IMAGE_MULTI_SCALE_DSP",
            "interpretation": (
                "Evaluates localized compression and noise-residual consistency across dense spatial blocks. "
                "Single-image analysis cannot prove object removal; optional reference comparison is required "
                "for authoritative scene-difference localization."
            ),
        }

    def _generate_ela_heatmap(self, diff: np.ndarray) -> str:
        """
        Generate a false-color localized ELA disparity heatmap as a compact Base64 JPEG string.
        Bright magenta/cyan highlights indicate high compression variance zones.
        """
        try:
            # Collapse to 2D magnitude
            mag = np.mean(diff, axis=2) if diff.ndim == 3 else diff
            p95 = np.percentile(mag, 98) + 1e-5
            norm = np.clip(mag / p95, 0.0, 1.0)

            # Map to cyber false-color palette: (Cyan -> Magenta -> Red)
            h_map, w_map = norm.shape
            rgb_map = np.zeros((h_map, w_map, 3), dtype=np.uint8)
            # R channel: high error
            rgb_map[:, :, 0] = (norm * 255).astype(np.uint8)
            # G channel: low error
            rgb_map[:, :, 1] = ((1.0 - np.abs(norm - 0.5) * 2.0) * 120).astype(np.uint8)
            # B channel: inverted/moderate error
            rgb_map[:, :, 2] = ((1.0 - norm) * 220 + norm * 80).astype(np.uint8)

            heat_pil = Image.fromarray(rgb_map)
            if max(h_map, w_map) > 256:
                scale = 256.0 / max(h_map, w_map)
                heat_pil = heat_pil.resize((int(w_map * scale), int(h_map * scale)), Image.Resampling.BILINEAR)

            buf = io.BytesIO()
            heat_pil.save(buf, format="JPEG", quality=80)
            b64_str = base64.b64encode(buf.getvalue()).decode("ascii")
            return b64_str
        except Exception as e_heat:
            logger.debug(f"Heatmap generation notice: {e_heat}")
            return ""

    def _detect_faces_and_analyze(self, img: Image.Image) -> Dict[str, Any]:
        """
        Multi-stage calibrated face detection, anthropomorphic verification, and tampering analysis.
        Separates face detection from face manipulation:
          1. High-precision cascade detection (alt2 / default) with balanced scaling and minimum size.
          2. Geometric and anthropomorphic validation (aspect ratio, skin chrominance in YCrCb/HSV, feature symmetry).
          3. Rejection of non-face false positives (text, paper, hands, textures, shadows).
          4. If 0 valid faces: return NOT_APPLICABLE with 0.0 anomaly score and no facial manipulation penalty.
          5. If valid faces present: evaluate localized microtexture smoothing and perimeter seam discontinuity.
        """
        rgb_img = img.convert("RGB")
        pixels = np.asarray(rgb_img)
        if pixels.size and np.all(pixels == pixels[0, 0]):
            return {
                "faces_detected": 0,
                "facial_forensics_applicable": False,
                "face_detection_status": "NO_FACE_DETECTED",
                "status": "No face detected; facial boundary and warping forensics not applicable",
                "facial_status_level": "NOMINAL",
                "facial_anomaly_score": 0.0,
                "face_boxes": [],
                "face_detection_confidence": 0.0,
            }

        cascade_candidates = []
        try:
            import cv2
            if hasattr(cv2, "data") and hasattr(cv2.data, "haarcascades"):
                cascade_candidates.append(os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_alt2.xml"))
                cascade_candidates.append(os.path.join(cv2.data.haarcascades, "haarcascade_frontalface_default.xml"))
        except Exception:
            pass

        cascade_candidates.append(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                "detection", "assets", "haarcascade_frontalface_default.xml"
            )
        )

        cascade_path = next((p for p in cascade_candidates if os.path.exists(p)), None)
        if not cascade_path:
            return {
                "faces_detected": 0,
                "facial_forensics_applicable": False,
                "face_detection_status": "DETECTOR_UNAVAILABLE",
                "status": "Face detector cascade unavailable; facial forensics not applicable",
                "facial_status_level": "NOMINAL",
                "facial_anomaly_score": 0.0,
                "face_boxes": [],
                "face_detection_confidence": 0.0,
            }

        try:
            import cv2
            face_cascade = cv2.CascadeClassifier(cascade_path)
            # Support color verification
            cv_bgr_full = cv2.cvtColor(np.array(rgb_img), cv2.COLOR_RGB2BGR)
            orig_h, orig_w = cv_bgr_full.shape[:2]

            scale_factor = 1.0
            if max(orig_h, orig_w) > 1024:
                scale_factor = 1024.0 / max(orig_h, orig_w)
                cv_bgr = cv2.resize(cv_bgr_full, (int(orig_w * scale_factor), int(orig_h * scale_factor)))
            else:
                cv_bgr = cv_bgr_full

            cv_gray = cv2.cvtColor(cv_bgr, cv2.COLOR_BGR2GRAY)
            cur_h, cur_w = cv_gray.shape[:2]

            min_side = min(cur_h, cur_w)
            if min_side < 120:
                min_face = max(16, int(min_side * 0.15))
                raw_faces = face_cascade.detectMultiScale(
                    cv_gray, scaleFactor=1.05, minNeighbors=3, minSize=(min_face, min_face)
                )
            else:
                min_face = max(40, min(80, int(min_side * 0.08)))
                raw_faces = face_cascade.detectMultiScale(
                    cv_gray, scaleFactor=1.10, minNeighbors=5, minSize=(min_face, min_face)
                )

            if len(raw_faces) == 0:
                return {
                    "faces_detected": 0,
                    "facial_forensics_applicable": False,
                    "face_detection_status": "NO_FACE_DETECTED",
                    "status": "No face detected; facial boundary and warping forensics not applicable",
                    "facial_status_level": "NOMINAL",
                    "facial_anomaly_score": 0.0,
                    "face_boxes": [],
                    "face_detection_confidence": 0.0,
                }

            # Optional eye cascade for anthropomorphic verification
            eye_cascade = None
            try:
                eye_path = os.path.join(getattr(cv2.data, "haarcascades", ""), "haarcascade_eye.xml")
                if os.path.exists(eye_path):
                    eye_cascade = cv2.CascadeClassifier(eye_path)
            except Exception:
                pass

            # Detect whether image has color information
            is_color = float(np.std(cv_bgr[:, :, 0] - cv_bgr[:, :, 1]) + np.std(cv_bgr[:, :, 1] - cv_bgr[:, :, 2])) > 4.0

            valid_faces = []
            for (fx, fy, fw, fh) in raw_faces:
                # 1. Anthropomorphic Aspect Ratio Check: human faces are roughly [0.65, 1.45]
                aspect_ratio = float(fw) / float(fh)
                if aspect_ratio < 0.65 or aspect_ratio > 1.45:
                    continue

                face_roi_gray = cv_gray[fy:fy + fh, fx:fx + fw]
                face_roi_bgr = cv_bgr[fy:fy + fh, fx:fx + fw]

                # 2. Skin Chromaticity Verification for color images
                if is_color:
                    ycrcb = cv2.cvtColor(face_roi_bgr, cv2.COLOR_BGR2YCrCb)
                    cr, cb = ycrcb[:, :, 1], ycrcb[:, :, 2]
                    # Standard Kovac / Peer / Chai skin boundaries in YCrCb
                    skin_mask = (cr >= 125) & (cr <= 180) & (cb >= 75) & (cb <= 140)
                    skin_frac = float(np.mean(skin_mask))
                    # Reject if virtually no skin tone in the candidate box (e.g. text on paper, foliage, desk)
                    if skin_frac < 0.08:
                        continue

                # 3. Horizontal Bilateral Symmetry Check
                half_w = fw // 2
                if half_w >= 8 and fh >= 12:
                    left_half = face_roi_gray[:, :half_w].astype(np.float32)
                    right_half = np.fliplr(face_roi_gray[:, fw - half_w:]).astype(np.float32)
                    std_l, std_r = float(np.std(left_half)), float(np.std(right_half))
                    if std_l > 1e-3 and std_r > 1e-3:
                        sym_corr = float(np.corrcoef(left_half.flatten(), right_half.flatten())[0, 1])
                    else:
                        sym_corr = 0.0

                    # If symmetry is negative or extremely low on low-contrast box, verify eye presence on standard res
                    if sym_corr < 0.10 and min_side >= 120:
                        has_eye = False
                        if eye_cascade is not None and not eye_cascade.empty():
                            upper_roi = face_roi_gray[:int(fh * 0.60), :]
                            eyes = eye_cascade.detectMultiScale(upper_roi, scaleFactor=1.1, minNeighbors=3, minSize=(int(fw * 0.15), int(fh * 0.15)))
                            has_eye = len(eyes) > 0
                        if not has_eye:
                            continue

                valid_faces.append((fx, fy, fw, fh))

            face_count = len(valid_faces)
            if face_count == 0:
                return {
                    "faces_detected": 0,
                    "facial_forensics_applicable": False,
                    "face_detection_status": "NO_FACE_DETECTED",
                    "status": "No face detected; facial boundary and warping forensics not applicable",
                    "facial_status_level": "NOMINAL",
                    "facial_anomaly_score": 0.0,
                    "face_boxes": [],
                    "face_detection_confidence": 0.0,
                }

            # Valid faces present: Proceed with forensic inspection
            face_boxes = []
            for (fx, fy, fw, fh) in valid_faces:
                face_boxes.append({
                    "ymin": round(float(fy) / cur_h, 3),
                    "xmin": round(float(fx) / cur_w, 3),
                    "ymax": round(float(fy + fh) / cur_h, 3),
                    "xmax": round(float(fx + fw) / cur_w, 3),
                    "box_pixels": [int(fx), int(fy), int(fw), int(fh)],
                })

            min_valid_face_dim = min(min(fw, fh) for (_, _, fw, fh) in valid_faces)
            if min_valid_face_dim < 44:
                return {
                    "faces_detected": face_count,
                    "facial_forensics_applicable": False,
                    "face_detection_status": "FACE_DETECTED",
                    "status": f"{face_count} face(s) detected; biometric warping forensics not applicable (compact face resolution: {min_valid_face_dim}px < 44px baseline)",
                    "facial_status_level": "NOMINAL",
                    "facial_anomaly_score": 0.0,
                    "face_boxes": face_boxes,
                    "face_detection_confidence": 0.88,
                }

            bg_lap_var = float(cv2.Laplacian(cv_gray, cv2.CV_32F).var()) + 1e-5
            facial_smoothing = False
            boundary_seam = False
            eye_disparity = False
            anomaly_score = 0.0
            face_lap_vals = []
            skin_lap_vals = []
            seam_ratios = []

            for (fx, fy, fw, fh) in valid_faces:
                face_roi = cv_gray[fy:fy + fh, fx:fx + fw]
                f_lap = float(cv2.Laplacian(face_roi, cv2.CV_32F).var())
                face_lap_vals.append(f_lap)

                sy1, sy2 = int(fh * 0.45), int(fh * 0.65)
                sx1, sx2 = int(fw * 0.30), int(fw * 0.70)
                skin_patch = face_roi[sy1:sy2, sx1:sx2]
                s_lap = float(cv2.Laplacian(skin_patch, cv2.CV_32F).var()) if skin_patch.size > 16 else f_lap
                skin_lap_vals.append(s_lap)

                # Waxy skin microtexture check
                if (s_lap / (f_lap + 1e-5) < self.config.face_skin_to_edge_ratio and
                        s_lap < self.config.face_skin_lap_min and
                        f_lap > self.config.face_edge_lap_min and
                        bg_lap_var > 30.0):
                    facial_smoothing = True
                    anomaly_score = max(anomaly_score, 0.30)

                # Boundary seam check (ring around face vs background)
                pad = max(4, int(min(fw, fh) * 0.08))
                py1, py2 = max(0, fy - pad), min(cur_h, fy + fh + pad)
                px1, px2 = max(0, fx - pad), min(cur_w, fx + fw + pad)
                outer_roi = cv_gray[py1:py2, px1:px2]
                if outer_roi.size > 0:
                    outer_lap = float(cv2.Laplacian(outer_roi, cv2.CV_32F).var())
                    seam_ratio = outer_lap / (f_lap + 1e-5)
                    seam_ratios.append(seam_ratio)
                    if seam_ratio >= self.config.face_seam_ratio_threshold and f_lap > 40.0:
                        boundary_seam = True
                        anomaly_score = max(anomaly_score, 0.25)

                # Eye catchlight asymmetry
                if eye_cascade is not None and not eye_cascade.empty():
                    eyes = eye_cascade.detectMultiScale(face_roi[:int(fh * 0.6), :])
                    if len(eyes) >= 2:
                        eyes = sorted(eyes, key=lambda e: e[0])[:2]
                        e1 = face_roi[eyes[0][1]:eyes[0][1] + eyes[0][3], eyes[0][0]:eyes[0][0] + eyes[0][2]]
                        e2 = face_roi[eyes[1][1]:eyes[1][1] + eyes[1][3], eyes[1][0]:eyes[1][0] + eyes[1][2]]
                        v1, v2 = float(np.var(e1)), float(np.var(e2))
                        eye_diff = abs(v1 - v2) / (max(v1, v2) + 1e-5)
                        if eye_diff > self.config.face_eye_asymmetry_threshold:
                            eye_disparity = True
                            anomaly_score = max(anomaly_score, 0.20)

            status_desc = f"{face_count} face(s) inspected across boundary seam and microtexture domains"
            if anomaly_score > 0.0:
                triggers = []
                if facial_smoothing:
                    triggers.append("synthetic microtexture smoothing")
                if boundary_seam:
                    triggers.append("boundary seam discontinuity")
                if eye_disparity:
                    triggers.append("bilateral eye catchlight disparity")
                status_desc = f"Facial anomalies detected in {', '.join(triggers)}"

            facial_status_level = "CRITICAL" if anomaly_score >= 0.40 else ("MODERATE" if anomaly_score >= 0.20 else "NOMINAL")
            return {
                "faces_detected": face_count,
                "facial_forensics_applicable": True,
                "face_detection_status": "FACE_DETECTED",
                "face_detection_confidence": 0.95,
                "status": status_desc,
                "facial_status_level": facial_status_level,
                "facial_anomaly_score": round(float(anomaly_score), 3),
                "facial_smoothing_detected": facial_smoothing,
                "boundary_seam_detected": boundary_seam,
                "eye_disparity_detected": eye_disparity,
                "face_lap_var": round(float(np.mean(face_lap_vals)), 1) if face_lap_vals else 0.0,
                "skin_lap_var": round(float(np.mean(skin_lap_vals)), 1) if skin_lap_vals else 0.0,
                "seam_ratio": round(float(np.mean(seam_ratios)), 2) if seam_ratios else 0.0,
                "face_boxes": face_boxes,
            }

        except Exception as cv_err:
            logger.debug(f"OpenCV face analysis notice: {cv_err}")
            return {
                "faces_detected": 0,
                "facial_forensics_applicable": False,
                "face_detection_status": "DETECTION_ERROR",
                "face_detection_confidence": 0.0,
                "status": f"No face detected (inspection neutral: {cv_err})",
                "facial_status_level": "NOMINAL",
                "facial_anomaly_score": 0.0,
                "face_boxes": [],
            }


# Global singleton provider
_image_forensics_engine: Optional[ImageForensicsEngine] = None


def get_image_forensics_engine() -> ImageForensicsEngine:
    global _image_forensics_engine
    if _image_forensics_engine is None:
        _image_forensics_engine = ImageForensicsEngine()
    return _image_forensics_engine
