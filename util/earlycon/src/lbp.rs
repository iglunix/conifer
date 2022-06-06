use ::limine::*;

static TERMINAL_REQUEST: LimineTerminalRequest = LimineTerminalRequest::new(0);

pub fn write_str(s: &str) {
    static mut CACHED: Option<&'static LimineTerminalResponse> = None;

    unsafe {
        if let Some(writer) = CACHED {
            let terminal = writer.terminals().unwrap().first().unwrap();
            writer.write().unwrap()(terminal, s);
        } else {
            let response = TERMINAL_REQUEST.get_response().get().unwrap();
            let terminal = response.terminals().unwrap().first().unwrap();
            let writer = response.write().unwrap();

            writer(&terminal, s);

            // initialize the cached response
            CACHED = Some(response);
        }
    }
}
