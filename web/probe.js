(() => {
    "use strict";

    const textEncoder = new TextEncoder();

    async function sha256(value) {
        const bytes = typeof value === "string" ? textEncoder.encode(value) : value;
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        return Array.from(new Uint8Array(digest))
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join("");
    }

    function safe(name, fn, fallback = null) {
        try {
            return fn();
        } catch (error) {
            return {
                unavailable: true,
                name,
                error: String(error?.message || error),
                fallback,
            };
        }
    }

    async function safeAsync(name, fn, fallback = null) {
        try {
            return await fn();
        } catch (error) {
            return {
                unavailable: true,
                name,
                error: String(error?.message || error),
                fallback,
            };
        }
    }

    function media(query) {
        return safe(`matchMedia:${query}`, () => matchMedia(query).matches, null);
    }

    function collectNavigator() {
        const nav = navigator;
        return {
            user_agent: nav.userAgent,
            app_name: nav.appName,
            app_version: nav.appVersion,
            platform: nav.platform,
            vendor: nav.vendor,
            product: nav.product,
            product_sub: nav.productSub,
            language: nav.language,
            languages: Array.from(nav.languages || []),
            cookie_enabled: nav.cookieEnabled,
            do_not_track: nav.doNotTrack,
            global_privacy_control: nav.globalPrivacyControl ?? null,
            webdriver: nav.webdriver,
            pdf_viewer_enabled: nav.pdfViewerEnabled ?? null,
            max_touch_points: nav.maxTouchPoints,
            hardware_concurrency: nav.hardwareConcurrency ?? null,
            device_memory_gb: nav.deviceMemory ?? null,
            plugins: Array.from(nav.plugins || []).map((plugin) => ({
                name: plugin.name,
                filename: plugin.filename,
                description: plugin.description,
            })),
            mime_types: Array.from(nav.mimeTypes || []).map((mime) => ({
                type: mime.type,
                suffixes: mime.suffixes,
                description: mime.description,
            })),
            java_enabled: safe("javaEnabled", () => nav.javaEnabled(), null),
            taint_enabled: safe("taintEnabled", () => nav.taintEnabled?.() ?? null, null),
        };
    }

    async function collectUaClientHints() {
        const data = navigator.userAgentData;
        if (!data) {
            return { supported: false };
        }

        const highEntropy = await safeAsync("UA-CH high entropy", async () => {
            if (!data.getHighEntropyValues) {
                return {};
            }

            return await data.getHighEntropyValues([
                "architecture",
                "bitness",
                "formFactors",
                "fullVersionList",
                "model",
                "platformVersion",
                "uaFullVersion",
                "wow64",
            ]);
        }, {});

        return {
            supported: true,
            brands: Array.from(data.brands || []),
            mobile: data.mobile,
            platform: data.platform,
            high_entropy: highEntropy,
        };
    }

    function collectScreen() {
        return {
            width: screen.width,
            height: screen.height,
            avail_width: screen.availWidth,
            avail_height: screen.availHeight,
            avail_left: screen.availLeft ?? null,
            avail_top: screen.availTop ?? null,
            color_depth: screen.colorDepth,
            pixel_depth: screen.pixelDepth,
            orientation: screen.orientation
                ? {
                      type: screen.orientation.type,
                      angle: screen.orientation.angle,
                  }
                : null,
            device_pixel_ratio: devicePixelRatio,
        };
    }

    function collectViewport() {
        const visual = window.visualViewport;
        return {
            inner_width: innerWidth,
            inner_height: innerHeight,
            outer_width: outerWidth,
            outer_height: outerHeight,
            screen_x: screenX,
            screen_y: screenY,
            page_x_offset: pageXOffset,
            page_y_offset: pageYOffset,
            visual_viewport: visual
                ? {
                      width: visual.width,
                      height: visual.height,
                      scale: visual.scale,
                      offset_left: visual.offsetLeft,
                      offset_top: visual.offsetTop,
                  }
                : null,
        };
    }

    function collectIntl() {
        const date = new Date("2026-08-17T12:34:56Z");
        const number = 1234567.89;
        const options = Intl.DateTimeFormat().resolvedOptions();

        return {
            timezone: options.timeZone,
            locale: options.locale,
            calendar: options.calendar,
            numbering_system: options.numberingSystem,
            hour_cycle: options.hourCycle ?? null,
            timezone_offset_minutes: new Date().getTimezoneOffset(),
            date_sample: new Intl.DateTimeFormat(undefined, {
                dateStyle: "full",
                timeStyle: "long",
            }).format(date),
            number_sample: new Intl.NumberFormat().format(number),
            currency_sample: new Intl.NumberFormat(undefined, {
                style: "currency",
                currency: "USD",
            }).format(number),
            plural_sample: [0, 1, 2, 5, 21].map((value) => [
                value,
                new Intl.PluralRules().select(value),
            ]),
            list_sample: safe(
                "Intl.ListFormat",
                () => new Intl.ListFormat().format(["alpha", "beta", "gamma"]),
                null,
            ),
            relative_time_sample: safe(
                "Intl.RelativeTimeFormat",
                () => new Intl.RelativeTimeFormat().format(-1, "day"),
                null,
            ),
        };
    }

    function collectMediaQueries() {
        const queries = [
            "(pointer: fine)",
            "(pointer: coarse)",
            "(any-pointer: fine)",
            "(any-pointer: coarse)",
            "(hover: hover)",
            "(any-hover: hover)",
            "(color-gamut: srgb)",
            "(color-gamut: p3)",
            "(color-gamut: rec2020)",
            "(dynamic-range: high)",
            "(video-dynamic-range: high)",
            "(prefers-color-scheme: dark)",
            "(prefers-color-scheme: light)",
            "(prefers-reduced-motion: reduce)",
            "(prefers-reduced-transparency: reduce)",
            "(prefers-contrast: more)",
            "(forced-colors: active)",
            "(inverted-colors: inverted)",
            "(display-mode: standalone)",
            "(display-mode: fullscreen)",
            "(update: fast)",
            "(update: slow)",
        ];

        return Object.fromEntries(queries.map((query) => [query, media(query)]));
    }

    function collectWebGl() {
        const canvas = document.createElement("canvas");
        const gl = canvas.getContext("webgl2") || canvas.getContext("webgl");
        if (!gl) {
            return { supported: false };
        }

        const debug = gl.getExtension("WEBGL_debug_renderer_info");
        const parameter = (value) => safe(`webgl:${value}`, () => gl.getParameter(value), null);

        const range = (value) => {
            const result = parameter(value);
            return result && typeof result.length === "number" ? Array.from(result) : result;
        };

        return {
            supported: true,
            context: typeof WebGL2RenderingContext !== "undefined" && gl instanceof WebGL2RenderingContext ? "webgl2" : "webgl",
            vendor: parameter(gl.VENDOR),
            renderer: parameter(gl.RENDERER),
            unmasked_vendor: debug ? parameter(debug.UNMASKED_VENDOR_WEBGL) : null,
            unmasked_renderer: debug ? parameter(debug.UNMASKED_RENDERER_WEBGL) : null,
            version: parameter(gl.VERSION),
            shading_language_version: parameter(gl.SHADING_LANGUAGE_VERSION),
            max_texture_size: parameter(gl.MAX_TEXTURE_SIZE),
            max_cube_map_texture_size: parameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
            max_renderbuffer_size: parameter(gl.MAX_RENDERBUFFER_SIZE),
            max_viewport_dims: range(gl.MAX_VIEWPORT_DIMS),
            max_vertex_attribs: parameter(gl.MAX_VERTEX_ATTRIBS),
            max_vertex_texture_image_units: parameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS),
            max_texture_image_units: parameter(gl.MAX_TEXTURE_IMAGE_UNITS),
            max_combined_texture_image_units: parameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS),
            aliased_line_width_range: range(gl.ALIASED_LINE_WIDTH_RANGE),
            aliased_point_size_range: range(gl.ALIASED_POINT_SIZE_RANGE),
            antialias: gl.getContextAttributes()?.antialias ?? null,
            extensions: (gl.getSupportedExtensions() || []).slice().sort(),
        };
    }

    async function collectWebGpu() {
        if (!navigator.gpu) {
            return { supported: false };
        }

        const adapter = await navigator.gpu.requestAdapter();
        if (!adapter) {
            return { supported: true, adapter: null };
        }

        const limits = {};
        for (const key of Object.keys(Object.getPrototypeOf(adapter.limits) || {})) {
            const value = adapter.limits[key];
            if (typeof value === "number") {
                limits[key] = value;
            }
        }

        for (const key in adapter.limits) {
            const value = adapter.limits[key];
            if (typeof value === "number") {
                limits[key] = value;
            }
        }

        const info = adapter.info
            ? {
                  vendor: adapter.info.vendor ?? null,
                  architecture: adapter.info.architecture ?? null,
                  device: adapter.info.device ?? null,
                  description: adapter.info.description ?? null,
              }
            : null;

        return {
            supported: true,
            features: Array.from(adapter.features || []).sort(),
            limits,
            info,
        };
    }

    async function collectCanvas() {
        const canvas = document.createElement("canvas");
        canvas.width = 420;
        canvas.height = 120;
        const context = canvas.getContext("2d");
        if (!context) {
            return { supported: false };
        }

        context.textBaseline = "alphabetic";
        context.fillStyle = "#f60";
        context.fillRect(18, 15, 140, 55);
        context.fillStyle = "#069";
        context.font = "18px 'Arial', 'Helvetica', sans-serif";
        context.fillText("Zorin Client Intelligence 🦀 𝛑 Ж", 12, 42);
        context.globalCompositeOperation = "multiply";
        context.fillStyle = "rgba(120, 60, 200, 0.73)";
        context.beginPath();
        context.arc(210, 55, 32, 0, Math.PI * 2);
        context.fill();
        context.strokeStyle = "rgba(2, 200, 120, .8)";
        context.lineWidth = 2.25;
        context.strokeRect(3.5, 3.5, 400, 100);

        const dataUrl = canvas.toDataURL();
        const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;

        return {
            supported: true,
            data_url_sha256: await sha256(dataUrl),
            pixel_sha256: await sha256(new Uint8Array(pixels.buffer)),
            text_metrics: safe("canvas text metrics", () => {
                const metrics = context.measureText("Zorin Client Intelligence 0123456789 Ж");
                return {
                    width: metrics.width,
                    actual_bounding_box_ascent: metrics.actualBoundingBoxAscent,
                    actual_bounding_box_descent: metrics.actualBoundingBoxDescent,
                };
            }, null),
        };
    }

    async function collectAudio() {
        const OfflineAudio = window.OfflineAudioContext || window.webkitOfflineAudioContext;
        if (!OfflineAudio) {
            return { supported: false };
        }

        const context = new OfflineAudio(1, 5000, 44100);
        const oscillator = context.createOscillator();
        oscillator.type = "triangle";
        oscillator.frequency.value = 10000;

        const compressor = context.createDynamicsCompressor();
        compressor.threshold.value = -50;
        compressor.knee.value = 40;
        compressor.ratio.value = 12;
        compressor.attack.value = 0;
        compressor.release.value = 0.25;

        oscillator.connect(compressor);
        compressor.connect(context.destination);
        oscillator.start(0);

        const rendered = await context.startRendering();
        const channel = rendered.getChannelData(0);
        const slice = channel.slice(1000, 5000);
        let absoluteSum = 0;
        for (const value of slice) {
            absoluteSum += Math.abs(value);
        }

        return {
            supported: true,
            sample_rate: rendered.sampleRate,
            length: rendered.length,
            absolute_sum: absoluteSum,
            samples_sha256: await sha256(new Uint8Array(slice.buffer)),
        };
    }

    function detectFonts() {
        const candidates = [
            "Arial",
            "Arial Black",
            "Calibri",
            "Cambria",
            "Candara",
            "Comic Sans MS",
            "Consolas",
            "Courier New",
            "Georgia",
            "Helvetica",
            "Impact",
            "Lucida Console",
            "Menlo",
            "Microsoft Sans Serif",
            "Monaco",
            "Noto Sans",
            "Noto Serif",
            "Roboto",
            "Segoe UI",
            "SF Pro Display",
            "Tahoma",
            "Times New Roman",
            "Trebuchet MS",
            "Ubuntu",
            "Verdana",
        ];
        const baseline = ["monospace", "sans-serif", "serif"];
        const text = "mmmmmmmmmmlliWWЖΩ0123456789";
        const size = "72px";
        const container = document.createElement("div");
        container.style.position = "absolute";
        container.style.left = "-10000px";
        container.style.top = "-10000px";
        container.style.visibility = "hidden";
        document.body.appendChild(container);

        const measure = (family) => {
            const span = document.createElement("span");
            span.textContent = text;
            span.style.fontSize = size;
            span.style.fontFamily = family;
            span.style.whiteSpace = "nowrap";
            container.appendChild(span);
            const result = [span.offsetWidth, span.offsetHeight];
            span.remove();
            return result;
        };

        const baseSizes = Object.fromEntries(baseline.map((name) => [name, measure(name)]));
        const available = [];

        for (const font of candidates) {
            const detected = baseline.some((base) => {
                const sizeWithFont = measure(`'${font}', ${base}`);
                const baseSize = baseSizes[base];
                return sizeWithFont[0] !== baseSize[0] || sizeWithFont[1] !== baseSize[1];
            });
            if (detected) {
                available.push(font);
            }
        }

        container.remove();
        return {
            method: "metric-comparison",
            tested: candidates,
            available,
            local_fonts_api_supported: typeof window.queryLocalFonts === "function",
        };
    }

    async function collectLocalFonts() {
        if (typeof window.queryLocalFonts !== "function") {
            return { supported: false };
        }

        const fonts = await window.queryLocalFonts();
        return {
            supported: true,
            count: fonts.length,
            fonts: fonts.map((font) => ({
                family: font.family,
                full_name: font.fullName,
                postscript_name: font.postscriptName,
                style: font.style,
            })),
        };
    }

    function collectMedia() {
        const video = document.createElement("video");
        const audio = document.createElement("audio");
        const mediaSource = window.MediaSource;
        const types = [
            "video/mp4; codecs=avc1.42E01E",
            "video/mp4; codecs=av01.0.05M.08",
            "video/mp4; codecs=hev1.1.6.L93.B0",
            "video/webm; codecs=vp8",
            "video/webm; codecs=vp9",
            "video/webm; codecs=av01.0.05M.08",
            "audio/mp4; codecs=mp4a.40.2",
            "audio/webm; codecs=opus",
            "audio/ogg; codecs=vorbis",
        ];

        return {
            codecs: Object.fromEntries(
                types.map((type) => [
                    type,
                    {
                        video_can_play: video.canPlayType(type),
                        audio_can_play: audio.canPlayType(type),
                        media_source: mediaSource?.isTypeSupported?.(type) ?? null,
                    },
                ]),
            ),
            picture_in_picture_enabled: document.pictureInPictureEnabled ?? null,
            media_capabilities: Boolean(navigator.mediaCapabilities),
        };
    }

    async function collectStorage() {
        const result = {
            cookie_enabled: navigator.cookieEnabled,
            local_storage: safe("localStorage", () => {
                const key = "__zci_probe__";
                localStorage.setItem(key, "1");
                localStorage.removeItem(key);
                return true;
            }, false),
            session_storage: safe("sessionStorage", () => {
                const key = "__zci_probe__";
                sessionStorage.setItem(key, "1");
                sessionStorage.removeItem(key);
                return true;
            }, false),
            indexed_db: Boolean(window.indexedDB),
            cache_storage: Boolean(window.caches),
            storage_manager: Boolean(navigator.storage),
        };

        if (navigator.storage?.estimate) {
            result.estimate = await safeAsync("storage.estimate", () => navigator.storage.estimate(), null);
        }

        if (navigator.storage?.persisted) {
            result.persisted = await safeAsync("storage.persisted", () => navigator.storage.persisted(), null);
        }

        return result;
    }

    async function collectPermissions() {
        if (!navigator.permissions?.query) {
            return { supported: false };
        }

        const names = [
            "geolocation",
            "notifications",
            "camera",
            "microphone",
            "clipboard-read",
            "clipboard-write",
            "accelerometer",
            "gyroscope",
            "magnetometer",
        ];
        const states = {};

        for (const name of names) {
            states[name] = await safeAsync(
                `permission:${name}`,
                async () => (await navigator.permissions.query({ name })).state,
                null,
            );
        }

        return { supported: true, states };
    }

    function collectNetwork() {
        const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (!connection) {
            return { supported: false };
        }

        return {
            supported: true,
            effective_type: connection.effectiveType ?? null,
            type: connection.type ?? null,
            downlink_mbps: connection.downlink ?? null,
            downlink_max_mbps: connection.downlinkMax ?? null,
            rtt_ms: connection.rtt ?? null,
            save_data: connection.saveData ?? null,
        };
    }

    async function collectBattery() {
        if (!navigator.getBattery) {
            return { supported: false };
        }
        const battery = await navigator.getBattery();
        return {
            supported: true,
            charging: battery.charging,
            level: battery.level,
            charging_time: battery.chargingTime,
            discharging_time: battery.dischargingTime,
        };
    }

    function collectPerformance() {
        const navigation = performance.getEntriesByType("navigation")[0];
        return {
            time_origin: performance.timeOrigin,
            now: performance.now(),
            navigation: navigation
                ? {
                      type: navigation.type,
                      next_hop_protocol: navigation.nextHopProtocol,
                      redirect_count: navigation.redirectCount,
                      transfer_size: navigation.transferSize,
                      encoded_body_size: navigation.encodedBodySize,
                      decoded_body_size: navigation.decodedBodySize,
                      dns_ms: navigation.domainLookupEnd - navigation.domainLookupStart,
                      connect_ms: navigation.connectEnd - navigation.connectStart,
                      tls_ms:
                          navigation.secureConnectionStart > 0
                              ? navigation.connectEnd - navigation.secureConnectionStart
                              : null,
                      response_ms: navigation.responseEnd - navigation.responseStart,
                  }
                : null,
            memory: performance.memory
                ? {
                      js_heap_size_limit: performance.memory.jsHeapSizeLimit,
                      total_js_heap_size: performance.memory.totalJSHeapSize,
                      used_js_heap_size: performance.memory.usedJSHeapSize,
                  }
                : null,
        };
    }

    function collectCapabilities() {
        const cssFeatures = [
            "backdrop-filter: blur(1px)",
            "display: grid",
            "display: subgrid",
            "container-type: inline-size",
            "font-variation-settings: normal",
            "text-wrap: balance",
            "animation-timeline: scroll()",
        ];

        return {
            secure_context: window.isSecureContext,
            cross_origin_isolated: window.crossOriginIsolated,
            shared_array_buffer: typeof SharedArrayBuffer !== "undefined",
            webassembly: typeof WebAssembly !== "undefined",
            wasm_streaming: typeof WebAssembly !== "undefined" && typeof WebAssembly.instantiateStreaming === "function",
            webgpu: Boolean(navigator.gpu),
            webgl2: safe(
                "WebGL2",
                () => Boolean(document.createElement("canvas").getContext("webgl2")),
                false,
            ),
            web_rtc: typeof RTCPeerConnection !== "undefined",
            web_socket: typeof WebSocket !== "undefined",
            web_transport: typeof WebTransport !== "undefined",
            service_worker: "serviceWorker" in navigator,
            bluetooth: "bluetooth" in navigator,
            usb: "usb" in navigator,
            hid: "hid" in navigator,
            serial: "serial" in navigator,
            nfc: "NDEFReader" in window,
            payment_request: "PaymentRequest" in window,
            credential_management: "credentials" in navigator,
            virtual_keyboard: "virtualKeyboard" in navigator,
            eye_dropper: "EyeDropper" in window,
            file_system_access: "showOpenFilePicker" in window,
            local_font_access: "queryLocalFonts" in window,
            cookie_enabled: navigator.cookieEnabled,
            css: Object.fromEntries(
                cssFeatures.map((feature) => {
                    const [property, value] = feature.split(":").map((part) => part.trim());
                    return [feature, CSS.supports(property, value)];
                }),
            ),
        };
    }

    function collectAutomation() {
        const suspiciousGlobals = [
            "__webdriver_evaluate",
            "__selenium_evaluate",
            "__webdriver_script_function",
            "__webdriver_script_func",
            "__webdriver_script_fn",
            "__fxdriver_evaluate",
            "__driver_unwrapped",
            "__webdriver_unwrapped",
            "__driver_evaluate",
            "__selenium_unwrapped",
            "_Selenium_IDE_Recorder",
            "callSelenium",
            "_selenium",
            "calledSelenium",
        ];

        return {
            webdriver: navigator.webdriver,
            chrome_object: Boolean(window.chrome),
            plugins_length: navigator.plugins?.length ?? null,
            mime_types_length: navigator.mimeTypes?.length ?? null,
            suspicious_globals: suspiciousGlobals.filter((name) => name in window),
            error_stack_sample: safe("Error.stack", () => String(new Error("zci").stack).split("\n").slice(0, 4), []),
        };
    }

    async function collectVoices() {
        if (!window.speechSynthesis) {
            return { supported: false };
        }

        let voices = speechSynthesis.getVoices();
        if (!voices.length) {
            await new Promise((resolve) => {
                const timer = setTimeout(resolve, 150);
                speechSynthesis.addEventListener(
                    "voiceschanged",
                    () => {
                        clearTimeout(timer);
                        resolve();
                    },
                    { once: true },
                );
            });
            voices = speechSynthesis.getVoices();
        }

        return {
            supported: true,
            count: voices.length,
            voices: voices.map((voice) => ({
                name: voice.name,
                lang: voice.lang,
                local_service: voice.localService,
                default: voice.default,
            })),
        };
    }

    function sanitizeReferrer(value) {
        if (!value) {
            return "";
        }
        return safe("referrer", () => {
            const url = new URL(value);
            url.username = "";
            url.password = "";
            url.search = "";
            url.hash = "";
            return url.toString();
        }, "");
    }

    function collectMisc() {
        return {
            history_length: history.length,
            referrer: sanitizeReferrer(document.referrer),
            visibility_state: document.visibilityState,
            document_character_set: document.characterSet,
            compat_mode: document.compatMode,
            quirks_mode: document.compatMode !== "CSS1Compat",
            touch_event_supported: "ontouchstart" in window,
            pointer_event_supported: "PointerEvent" in window,
            device_orientation_supported: "DeviceOrientationEvent" in window,
            device_motion_supported: "DeviceMotionEvent" in window,
            clipboard_supported: Boolean(navigator.clipboard),
            share_supported: typeof navigator.share === "function",
            locks_supported: Boolean(navigator.locks),
            scheduling_supported: Boolean(navigator.scheduling),
        };
    }

    async function collectSensitive(options = {}) {
        const result = {
            explicit: true,
            collected_at: new Date().toISOString(),
        };

        if (options.geolocation) {
            result.geolocation = await safeAsync("geolocation", () => new Promise((resolve, reject) => {
                if (!navigator.geolocation) {
                    resolve({ supported: false });
                    return;
                }
                navigator.geolocation.getCurrentPosition(
                    (position) => resolve({
                        supported: true,
                        latitude: position.coords.latitude,
                        longitude: position.coords.longitude,
                        accuracy_m: position.coords.accuracy,
                        altitude_m: position.coords.altitude,
                        altitude_accuracy_m: position.coords.altitudeAccuracy,
                        heading: position.coords.heading,
                        speed_mps: position.coords.speed,
                        timestamp: position.timestamp,
                    }),
                    reject,
                    {
                        enableHighAccuracy: Boolean(options.highAccuracy),
                        timeout: 8000,
                        maximumAge: 0,
                    },
                );
            }), { supported: false });
        }

        if (options.localFonts) {
            result.local_fonts = await safeAsync("local-font-access", collectLocalFonts, { supported: false });
        }

        if (options.mediaDevices) {
            result.media_devices = await safeAsync("media-devices", async () => {
                if (!navigator.mediaDevices?.enumerateDevices) {
                    return { supported: false };
                }
                const devices = await navigator.mediaDevices.enumerateDevices();
                return {
                    supported: true,
                    devices: await Promise.all(devices.map(async (device) => ({
                        kind: device.kind,
                        label: device.label || null,
                        device_id_hash: device.deviceId ? await sha256(device.deviceId) : null,
                        group_id_hash: device.groupId ? await sha256(device.groupId) : null,
                    }))),
                };
            }, { supported: false });
        }

        if (options.keyboardLayout) {
            result.keyboard_layout = await safeAsync("keyboard-layout", async () => {
                if (!navigator.keyboard?.getLayoutMap) {
                    return { supported: false };
                }
                const map = await navigator.keyboard.getLayoutMap();
                return {
                    supported: true,
                    entries: Array.from(map.entries()),
                };
            }, { supported: false });
        }

        if (options.webRtcCandidates) {
            result.web_rtc_candidates = await safeAsync("webrtc-candidates", async () => {
                if (typeof RTCPeerConnection === "undefined") {
                    return { supported: false };
                }
                const connection = new RTCPeerConnection({ iceServers: [] });
                const candidates = [];
                connection.createDataChannel("zci");
                connection.addEventListener("icecandidate", (event) => {
                    if (event.candidate?.candidate && candidates.length < 16) {
                        candidates.push(event.candidate.candidate);
                    }
                });
                const offer = await connection.createOffer();
                await connection.setLocalDescription(offer);
                await new Promise((resolve) => setTimeout(resolve, 750));
                connection.close();
                return { supported: true, candidates };
            }, { supported: false });
        }

        return result;
    }

    async function observe(options = {}) {
        const endpoint = options.endpoint || "/api/v1/observe";
        const probe = options.probe || await collect({ mode: options.mode || "full" });
        if (options.sensitive) {
            probe.sensitive = await collectSensitive(options.sensitive);
        }

        const headers = {
            "content-type": "application/json",
        };
        if (options.siteKey) {
            headers["x-zci-site-key"] = options.siteKey;
        }

        const response = await fetch(endpoint, {
            method: "POST",
            headers,
            body: JSON.stringify(probe),
            credentials: "omit",
            cache: "no-store",
            redirect: "error",
        });
        if (!response.ok) {
            throw new Error(`ZCI observe failed: HTTP ${response.status}`);
        }
        return await response.json();
    }

    function applyCollectionMode(probe, mode) {
        if (mode === "full") {
            return probe;
        }

        if (mode === "security") {
            return {
                ...probe,
                battery: { omitted_by_mode: true },
                voices: { omitted_by_mode: true },
                performance: {
                    navigation: probe.performance?.navigation ?? null,
                    omitted_high_variance_fields: true,
                },
            };
        }

        if (mode === "essential") {
            return {
                ...probe,
                viewport: { omitted_by_mode: true },
                media_queries: { omitted_by_mode: true },
                webgl: { omitted_by_mode: true },
                webgpu: { omitted_by_mode: true },
                canvas: { omitted_by_mode: true },
                audio: { omitted_by_mode: true },
                fonts: { omitted_by_mode: true },
                media: { omitted_by_mode: true },
                storage: { omitted_by_mode: true },
                permissions: { omitted_by_mode: true },
                battery: { omitted_by_mode: true },
                performance: { omitted_by_mode: true },
                voices: { omitted_by_mode: true },
                automation: { webdriver: navigator.webdriver },
            };
        }

        throw new Error(`Unknown ZCI collection mode: ${mode}`);
    }

    async function collect(options = {}) {
        const mode = options.mode || "full";
        const [uaCh, webgpu, canvas, audio, storage, permissions, battery, voices] = await Promise.all([
            collectUaClientHints(),
            safeAsync("webgpu", collectWebGpu, { supported: false }),
            safeAsync("canvas", collectCanvas, { supported: false }),
            safeAsync("audio", collectAudio, { supported: false }),
            safeAsync("storage", collectStorage, {}),
            safeAsync("permissions", collectPermissions, {}),
            safeAsync("battery", collectBattery, { supported: false }),
            safeAsync("voices", collectVoices, { supported: false }),
        ]);

        const probe = {
            schema: "zci-browser-probe/2",
            collection_mode: mode,
            collected_at: new Date().toISOString(),
            navigator: collectNavigator(),
            user_agent_client_hints: uaCh,
            screen: collectScreen(),
            viewport: collectViewport(),
            intl: collectIntl(),
            media_queries: collectMediaQueries(),
            webgl: safe("webgl", collectWebGl, { supported: false }),
            webgpu,
            canvas,
            audio,
            fonts: safe("fonts", detectFonts, {}),
            media: collectMedia(),
            storage,
            permissions,
            network: collectNetwork(),
            battery,
            performance: collectPerformance(),
            capabilities: collectCapabilities(),
            automation: collectAutomation(),
            voices,
            misc: collectMisc(),
            sensitive: {},
        };

        return applyCollectionMode(probe, mode);
    }

    window.ZCI = Object.freeze({
        collect,
        collectSensitive,
        collectLocalFonts,
        observe,
    });
})();
