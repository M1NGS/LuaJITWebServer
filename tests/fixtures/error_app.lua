-- Minimal app for log-channel tests: /boom raises a Lua error so the C host
-- emits a real ERROR record (handler error) through log_error.
return {
  handle = function(req, res)
    if req.path == "/boom" then
      error("intentional handler error")
    end
    return { status = 200, body = "ok" }
  end,
}
