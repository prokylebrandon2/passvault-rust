//! Silk for Android: a Slint UI over `silk-core`, with a thin JNI bridge to the Java glue.
#![cfg(target_os = "android")]

mod bridge;
mod state;
mod ui;

slint::include_modules!();

#[no_mangle]
fn android_main(app: slint::android::AndroidApp) {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("silk")
            .with_max_level(log::LevelFilter::Info),
    );
    std::panic::set_hook(Box::new(|info| log::error!("panic: {info}")));
    let _ = slint::android::init(app.clone());
    bridge::init(&app);
    let dir = app
        .internal_data_path()
        .unwrap_or_else(|| std::path::PathBuf::from("/data/local/tmp"));
    ui::run(dir);
}
