// 1. Compile the Slint UI.
// 2. Render the app icon procedurally as raw 64px RGBA for the title bar.
//    The launcher icon PNGs in res/ were rendered once from the same drawing (sample()) at Android's mipmap sizes.
use std::path::PathBuf;

const SS: u32 = 4; // supersampling per axis

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let config = slint_build::CompilerConfiguration::new().with_style("material".into());
    slint_build::compile_with_config("ui/app.slint", config).unwrap();
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("icon64.rgba"), render(64).concat()).unwrap();
}

// ---- drawing: signed distance shapes in unit space, composited premultiplied ----

fn rrect(x: f32, y: f32, cx: f32, cy: f32, hw: f32, hh: f32, r: f32) -> f32 {
    let qx = (x - cx).abs() - hw + r;
    let qy = (y - cy).abs() - hh + r;
    (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt() + qx.max(qy).min(0.0) - r
}

fn over(dst: &mut [f32; 4], rgb: [f32; 3], a: f32) {
    for i in 0..3 {
        dst[i] = rgb[i] * a + dst[i] * (1.0 - a);
    }
    dst[3] = a + dst[3] * (1.0 - a);
}

fn rgb(r: u8, g: u8, b: u8) -> [f32; 3] {
    [r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0]
}

// Docker-ish (not the trademarked whale): Docker-blue tile, a pyramid of shipping containers
// on a cargo hull, riding a wave. n = target pixel size: small icons drop the fine detail.
fn sample(x: f32, y: f32, n: u32) -> [f32; 4] {
    let mut c = [0.0; 4];
    let tile = rrect(x, y, 0.5, 0.5, 0.47, 0.47, 0.22);
    if tile >= 0.0 {
        return c;
    }
    // Tile: Docker blue, lighter top-left to deeper bottom-right, soft top gloss.
    let t = (x * 0.35 + y * 0.65).clamp(0.0, 1.0);
    let (a, b) = (rgb(36, 150, 237), rgb(18, 84, 214));
    let gloss = (1.0 - y / 0.5).max(0.0) * 0.08;
    over(&mut c, [0, 1, 2].map(|i| (a[i] + (b[i] - a[i]) * t + gloss).min(1.0)), 1.0);

    // Containers: 3 / 2 / 1 pyramid, white with corrugation ridges; the top one is green ("running").
    let (hw, hh) = (0.085, 0.06);
    let boxes = [(0.29, 0.555), (0.50, 0.555), (0.71, 0.555), (0.395, 0.425), (0.605, 0.425), (0.50, 0.295)];
    for (k, &(cx, cy)) in boxes.iter().enumerate() {
        if rrect(x, y, cx, cy + 0.02, hw, hh, 0.02) < 0.0 {
            over(&mut c, [0.0; 3], 0.18); // drop shadow
        }
        if rrect(x, y, cx, cy, hw, hh, 0.02) < 0.0 {
            let body = if k == 5 { rgb(57, 211, 120) } else { rgb(247, 250, 255) };
            over(&mut c, body, 1.0);
            // Vertical ridges like a real container's sides (only where there are pixels to show them).
            let ridge = ((x - cx + hw) / (2.0 * hw) * 4.0).fract();
            if n >= 32 && (ridge < 0.14) && (x - cx).abs() < hw - 0.02 && (y - cy).abs() < hh - 0.018 {
                over(&mut c, [0.0; 3], 0.16);
            }
        }
    }

    // Hull: navy trapezoid under the containers.
    let (top, bottom) = (0.635, 0.745);
    if y > top && y < bottom {
        let k = (y - top) / (bottom - top);
        let half = 0.36 - 0.09 * k;
        if (x - 0.5).abs() < half {
            over(&mut c, rgb(10, 45, 120), 1.0);
        }
    }

    // Water: a white wave line with lighter water below it.
    let wave = 0.79 + 0.022 * (x * std::f32::consts::TAU * 2.0).sin();
    if y > wave {
        over(&mut c, rgb(150, 210, 255), 0.45);
    }
    if (y - wave).abs() < 0.018f32.max(0.6 / n as f32) {
        over(&mut c, rgb(255, 255, 255), 0.9);
    }
    c
}

// n x n straight-alpha RGBA, top-down.
fn render(n: u32) -> Vec<[u8; 4]> {
    let mut px = Vec::with_capacity((n * n) as usize);
    for py in 0..n {
        for pxi in 0..n {
            let mut acc = [0.0f32; 4];
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (pxi as f32 + (sx as f32 + 0.5) / SS as f32) / n as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) / n as f32;
                    let s = sample(x, y, n);
                    for i in 0..4 {
                        acc[i] += s[i] / (SS * SS) as f32;
                    }
                }
            }
            let a = acc[3];
            let un = |v: f32| if a > 0.0 { (v / a * 255.0).round().min(255.0) as u8 } else { 0 };
            px.push([un(acc[0]), un(acc[1]), un(acc[2]), (a * 255.0).round() as u8]);
        }
    }
    px
}
