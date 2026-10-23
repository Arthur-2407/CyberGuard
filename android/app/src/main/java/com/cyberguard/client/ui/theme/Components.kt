package com.cyberguard.client.ui.theme

import androidx.compose.animation.core.*
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CutCornerShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.sin

/**
 * Tactical Cybernetic Card with optical reticle corner accents and subtle holographic depth.
 */
@Composable
fun CyberGuardCard(
    modifier: Modifier = Modifier,
    containerColor: Color = ElevatedSurface,
    borderColor: Color = HolographicGlowBorder,
    showCornerReticles: Boolean = true,
    cornerReticleColor: Color = CyberNeonCyan.copy(alpha = 0.5f),
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) {
    val shape = CutCornerShape(10.dp)
    val border = BorderStroke(1.dp, borderColor)
    
    val reticleModifier = if (showCornerReticles) {
        Modifier.drawBehind {
            val bracketLength = 12.dp.toPx()
            val strokeWidth = 1.8.dp.toPx()
            val pad = 1.dp.toPx()
            
            // Top-Left ┌
            drawLine(cornerReticleColor, Offset(pad, pad), Offset(pad + bracketLength, pad), strokeWidth, StrokeCap.Square)
            drawLine(cornerReticleColor, Offset(pad, pad), Offset(pad, pad + bracketLength), strokeWidth, StrokeCap.Square)
            
            // Top-Right ┐
            drawLine(cornerReticleColor, Offset(size.width - pad, pad), Offset(size.width - pad - bracketLength, pad), strokeWidth, StrokeCap.Square)
            drawLine(cornerReticleColor, Offset(size.width - pad, pad), Offset(size.width - pad, pad + bracketLength), strokeWidth, StrokeCap.Square)
            
            // Bottom-Left └
            drawLine(cornerReticleColor, Offset(pad, size.height - pad), Offset(pad + bracketLength, size.height - pad), strokeWidth, StrokeCap.Square)
            drawLine(cornerReticleColor, Offset(pad, size.height - pad), Offset(pad, size.height - pad - bracketLength), strokeWidth, StrokeCap.Square)
            
            // Bottom-Right ┘
            drawLine(cornerReticleColor, Offset(size.width - pad, size.height - pad), Offset(size.width - pad - bracketLength, size.height - pad), strokeWidth, StrokeCap.Square)
            drawLine(cornerReticleColor, Offset(size.width - pad, size.height - pad), Offset(size.width - pad, size.height - pad - bracketLength), strokeWidth, StrokeCap.Square)
        }
    } else Modifier

    if (onClick != null) {
        Surface(
            modifier = modifier.then(reticleModifier),
            shape = shape,
            color = containerColor,
            border = border,
            onClick = onClick
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                content()
            }
        }
    } else {
        Surface(
            modifier = modifier.then(reticleModifier),
            shape = shape,
            color = containerColor,
            border = border
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                content()
            }
        }
    }
}

@Composable
fun VoiceGuardCard(
    modifier: Modifier = Modifier,
    containerColor: Color = ElevatedSurface,
    borderColor: Color = HolographicGlowBorder,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit
) = CyberGuardCard(
    modifier = modifier,
    containerColor = containerColor,
    borderColor = borderColor,
    onClick = onClick,
    content = content
)

/**
 * Tactical Section Header with holographic brackets and laser indicator
 */
@Composable
fun SectionHeader(title: String, modifier: Modifier = Modifier) {
    Row(
        modifier = modifier.padding(bottom = 10.dp, top = 18.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .width(3.dp)
                .height(13.dp)
                .background(
                    brush = Brush.verticalGradient(
                        colors = listOf(CyberNeonCyan, CyberBlue)
                    ),
                    shape = CutCornerShape(1.dp)
                )
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = "[ $title ]".uppercase(),
            style = MaterialTheme.typography.labelMedium.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
            ),
            color = CyberBlue,
            letterSpacing = 1.3.sp
        )
    }
}

/**
 * Hyper-Advanced Tactical Status Badge with optional animated beacon pulse
 */
@Composable
fun StatusBadge(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
    isPulsing: Boolean = true
) {
    val infiniteTransition = rememberInfiniteTransition(label = "badgePulse")
    val beaconScale by infiniteTransition.animateFloat(
        initialValue = 0.8f,
        targetValue = 1.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(1100, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "beaconScale"
    )
    val beaconAlpha by infiniteTransition.animateFloat(
        initialValue = 0.45f,
        targetValue = 0.95f,
        animationSpec = infiniteRepeatable(
            animation = tween(1100, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "beaconAlpha"
    )

    Surface(
        modifier = modifier,
        shape = CutCornerShape(4.dp),
        color = color.copy(alpha = 0.12f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.5f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 9.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(10.dp),
                contentAlignment = Alignment.Center
            ) {
                if (isPulsing) {
                    Canvas(modifier = Modifier.size(10.dp)) {
                        drawCircle(
                            color = color.copy(alpha = beaconAlpha * 0.4f),
                            radius = (size.minDimension / 2f) * beaconScale
                        )
                    }
                }
                Box(
                    modifier = Modifier
                        .size(5.dp)
                        .background(color, CutCornerShape(1.dp))
                )
            }
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = text.uppercase(),
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 10.sp
                ),
                color = color
            )
        }
    }
}

/**
 * High-Density Metric Display with Monospace Numerical Readout
 */
@Composable
fun MetricDisplay(
    label: String,
    value: String,
    color: Color = TextPrimary,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier) {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                letterSpacing = 0.8.sp
            ),
            color = TextTertiary
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.displaySmall.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp
            ),
            color = color
        )
    }
}

/**
 * Reusable Telemetry Status Label-Value Row
 */
@Composable
fun StatusRow(label: String, value: String, color: Color) {
    Column {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 9.sp,
                letterSpacing = 0.8.sp
            ),
            color = TextTertiary
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            ),
            color = color
        )
    }
}

/**
 * Tactical Engine HUD Chip
 */
@Composable
fun TacticalEngineChip(
    code: String,
    label: String,
    isArmed: Boolean,
    modifier: Modifier = Modifier
) {
    val accentColor = if (isArmed) StatusOnline else StatusOffline
    Surface(
        modifier = modifier,
        shape = CutCornerShape(4.dp),
        color = HighlightSurface,
        border = BorderStroke(1.dp, accentColor.copy(alpha = 0.4f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(5.dp)
                    .background(accentColor, CutCornerShape(1.dp))
            )
            Spacer(modifier = Modifier.width(6.dp))
            Column {
                Text(
                    text = code,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 9.sp,
                        fontWeight = FontWeight.Bold
                    ),
                    color = accentColor
                )
                Text(
                    text = label,
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 8.sp
                    ),
                    color = TextTertiary
                )
            }
        }
    }
}

/**
 * Animated Photonic Forensic Scanning Chamber with vertical laser sweep and targeting reticle.
 */
@Composable
fun AnimatedScanningChamber(
    modifier: Modifier = Modifier,
    height: Dp = 190.dp,
    isScanning: Boolean = false,
    content: @Composable BoxScope.() -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "scannerLaser")
    val laserProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = if (isScanning) 1000 else 2400, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "laserPos"
    )

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(height)
            .clip(CutCornerShape(12.dp))
            .background(DeepSpaceBackground)
            .border(1.dp, CyberBlue.copy(alpha = 0.4f), CutCornerShape(12.dp))
    ) {
        // Holographic Grid Background & Corner Reticles
        Canvas(modifier = Modifier.fillMaxSize()) {
            val step = 20.dp.toPx()
            val gridColor = CyberBlue.copy(alpha = 0.04f)
            
            // Grid lines
            var x = 0f
            while (x <= size.width) {
                drawLine(gridColor, Offset(x, 0f), Offset(x, size.height), 1f)
                x += step
            }
            var y = 0f
            while (y <= size.height) {
                drawLine(gridColor, Offset(0f, y), Offset(size.width, y), 1f)
                y += step
            }

            // Tactical Corner Brackets
            val bLen = 16.dp.toPx()
            val sWidth = 2.dp.toPx()
            val bColor = CyberNeonCyan.copy(alpha = 0.75f)

            // Top-Left
            drawLine(bColor, Offset(0f, 0f), Offset(bLen, 0f), sWidth)
            drawLine(bColor, Offset(0f, 0f), Offset(0f, bLen), sWidth)
            // Top-Right
            drawLine(bColor, Offset(size.width, 0f), Offset(size.width - bLen, 0f), sWidth)
            drawLine(bColor, Offset(size.width, 0f), Offset(size.width, bLen), sWidth)
            // Bottom-Left
            drawLine(bColor, Offset(0f, size.height), Offset(bLen, size.height), sWidth)
            drawLine(bColor, Offset(0f, size.height), Offset(0f, size.height - bLen), sWidth)
            // Bottom-Right
            drawLine(bColor, Offset(size.width, size.height), Offset(size.width - bLen, size.height), sWidth)
            drawLine(bColor, Offset(size.width, size.height), Offset(size.width, size.height - bLen), sWidth)

            // Sweeping Laser Beam
            val laserY = size.height * laserProgress
            val laserColor = if (isScanning) StatusCritical else CyberNeonCyan
            
            // Laser glow gradient
            drawRect(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        laserColor.copy(alpha = 0f),
                        laserColor.copy(alpha = if (isScanning) 0.35f else 0.15f),
                        laserColor.copy(alpha = 0f)
                    ),
                    startY = (laserY - 24.dp.toPx()).coerceAtLeast(0f),
                    endY = (laserY + 24.dp.toPx()).coerceAtMost(size.height)
                ),
                topLeft = Offset(0f, (laserY - 24.dp.toPx()).coerceAtLeast(0f)),
                size = Size(size.width, 48.dp.toPx())
            )
            // Thin laser beam
            drawLine(
                color = laserColor.copy(alpha = if (isScanning) 0.95f else 0.7f),
                start = Offset(0f, laserY),
                end = Offset(size.width, laserY),
                strokeWidth = 2.dp.toPx()
            )
        }

        // Child Content
        content()
    }
}

/**
 * Animated Real-Time Energy Pulse Wave
 */
@Composable
fun AnimatedEnergyWave(
    modifier: Modifier = Modifier,
    lineColor: Color = CyberNeonCyan,
    waveCount: Int = 3
) {
    val infiniteTransition = rememberInfiniteTransition(label = "energyWave")
    val phase by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = (2 * Math.PI).toFloat(),
        animationSpec = infiniteRepeatable(
            animation = tween(2200, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "wavePhase"
    )

    Canvas(modifier = modifier.fillMaxWidth().height(26.dp)) {
        val path = Path()
        val midY = size.height / 2f
        val amplitude = size.height * 0.35f
        
        path.moveTo(0f, midY)
        val step = 4f
        var x = 0f
        while (x <= size.width) {
            val progress = x / size.width
            val y = midY + amplitude * sin(progress * (2 * Math.PI * waveCount) + phase).toFloat()
            path.lineTo(x, y)
            x += step
        }

        drawPath(
            path = path,
            color = lineColor.copy(alpha = 0.7f),
            style = Stroke(width = 1.5.dp.toPx(), cap = StrokeCap.Round)
        )
    }
}

/**
 * High-Contrast Cybernetic Text Field with luminous focus border and clear labels
 */
@Composable
fun CyberTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String? = null,
    singleLine: Boolean = true,
    isError: Boolean = false,
    errorMessage: String? = null,
    visualTransformation: androidx.compose.ui.text.input.VisualTransformation = androidx.compose.ui.text.input.VisualTransformation.None,
    keyboardOptions: androidx.compose.foundation.text.KeyboardOptions = androidx.compose.foundation.text.KeyboardOptions.Default,
    keyboardActions: androidx.compose.foundation.text.KeyboardActions = androidx.compose.foundation.text.KeyboardActions.Default,
    leadingIcon: @Composable (() -> Unit)? = null,
    trailingIcon: @Composable (() -> Unit)? = null
) {
    Column(modifier = modifier) {
        Text(
            text = label.uppercase(),
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 10.sp,
                letterSpacing = 1.sp
            ),
            color = if (isError) StatusCritical else CyberNeonCyan
        )
        Spacer(modifier = Modifier.height(5.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = placeholder?.let {
                { Text(it, style = MaterialTheme.typography.bodySmall.copy(color = TextTertiary)) }
            },
            singleLine = singleLine,
            isError = isError,
            visualTransformation = visualTransformation,
            keyboardOptions = keyboardOptions,
            keyboardActions = keyboardActions,
            leadingIcon = leadingIcon,
            trailingIcon = trailingIcon,
            shape = CutCornerShape(6.dp),
            textStyle = MaterialTheme.typography.bodyMedium.copy(
                color = TextPrimary,
                fontFamily = FontFamily.Monospace
            ),
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = FieldBackground,
                unfocusedContainerColor = FieldBackground,
                errorContainerColor = FieldBackground,
                focusedBorderColor = CyberNeonCyan,
                unfocusedBorderColor = FieldBorderIdle,
                errorBorderColor = StatusCritical,
                cursorColor = CyberNeonCyan
            ),
            modifier = Modifier.fillMaxWidth()
        )
        if (isError && !errorMessage.isNullOrBlank()) {
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = errorMessage,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp
                ),
                color = StatusCritical
            )
        }
    }
}

enum class CyberButtonVariant {
    PRIMARY,
    OUTLINED,
    SECONDARY,
    DESTRUCTIVE
}

/**
 * Premium Tactical Button with explicit states and loading indicator
 */
@Composable
fun CyberButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    variant: CyberButtonVariant = CyberButtonVariant.PRIMARY,
    enabled: Boolean = true,
    isLoading: Boolean = false,
    icon: @Composable (() -> Unit)? = null
) {
    val containerColor = when (variant) {
        CyberButtonVariant.PRIMARY -> if (enabled) CyberNeonCyan else HighlightSurface
        CyberButtonVariant.OUTLINED -> HighlightSurface
        CyberButtonVariant.SECONDARY -> HighlightSurface
        CyberButtonVariant.DESTRUCTIVE -> if (enabled) StatusCritical.copy(alpha = 0.2f) else HighlightSurface
    }

    val contentColor = when (variant) {
        CyberButtonVariant.PRIMARY -> if (enabled) DeepSpaceBackground else TextTertiary
        CyberButtonVariant.OUTLINED -> if (enabled) CyberNeonCyan else TextTertiary
        CyberButtonVariant.SECONDARY -> if (enabled) TextPrimary else TextTertiary
        CyberButtonVariant.DESTRUCTIVE -> if (enabled) StatusCritical else TextTertiary
    }

    val border = when (variant) {
        CyberButtonVariant.OUTLINED -> BorderStroke(1.dp, if (enabled) CyberNeonCyan else DividerColor)
        CyberButtonVariant.DESTRUCTIVE -> BorderStroke(1.dp, if (enabled) StatusCritical else DividerColor)
        CyberButtonVariant.SECONDARY -> BorderStroke(1.dp, DividerColor)
        CyberButtonVariant.PRIMARY -> if (!enabled) BorderStroke(1.dp, DividerColor) else null
    }

    Button(
        onClick = onClick,
        enabled = enabled && !isLoading,
        shape = CutCornerShape(6.dp),
        border = border,
        colors = ButtonDefaults.buttonColors(
            containerColor = containerColor,
            contentColor = contentColor,
            disabledContainerColor = HighlightSurface,
            disabledContentColor = TextTertiary
        ),
        modifier = modifier
    ) {
        if (isLoading) {
            CircularProgressIndicator(
                modifier = Modifier.size(14.dp),
                color = contentColor,
                strokeWidth = 2.dp
            )
            Spacer(modifier = Modifier.width(8.dp))
        } else if (icon != null) {
            icon()
            Spacer(modifier = Modifier.width(6.dp))
        }
        Text(
            text = text.uppercase(),
            style = MaterialTheme.typography.labelSmall.copy(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 11.sp,
                letterSpacing = 1.sp
            )
        )
    }
}

/**
 * Draws a 4-point radiant diamond star lens flare glint.
 */
fun DrawScope.drawStarGlint(center: Offset, radius: Float, color: Color) {
    val cx = center.x
    val cy = center.y

    val starPath = Path().apply {
        moveTo(cx, cy - radius)
        quadraticBezierTo(cx, cy, cx + radius, cy)
        quadraticBezierTo(cx, cy, cx, cy + radius)
        quadraticBezierTo(cx, cy, cx - radius, cy)
        quadraticBezierTo(cx, cy, cx, cy - radius)
        close()
    }

    drawPath(path = starPath, color = color)
    drawCircle(
        brush = Brush.radialGradient(
            colors = listOf(Color.White, color.copy(alpha = 0.6f), Color.Transparent),
            center = center,
            radius = radius * 1.5f
        )
    )
}

