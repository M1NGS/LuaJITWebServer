-- Regression fixture for Lua API semantics (query/headers/text/header map/204/304).
local function handle(req, res)
  if req.path == "/query" then
    return { status = 200, body = req.query or "" }
  elseif req.path == "/header" then
    return { status = 200, body = req.headers["X-Test"] or "-" }
  elseif req.path == "/text" then
    local s = req:text(4 * 1024 * 1024)
    return { status = 200, body = "len=" .. #s }
  elseif req.path == "/timeout0" then
    res:set_timeout(0)
    return { status = 200, body = "ok" }
  elseif req.path == "/header-map" then
    res:write_head(200, { ["X-Map"] = "yes" }, 2)
    res:write("ok")
    res:finish()
    return
  elseif req.path == "/queue" then
    res:write_head(200, { { "X-Queue", tostring(res:queue_size()) } }, 0)
    res:finish()
    return
  elseif req.path == "/204" then
    return { status = 204, headers = { { "X-No", "1" } }, body = "ignored" }
  elseif req.path == "/304" then
    return { status = 304, body = "ignored" }
  elseif req.path == "/method" then
    return { status = 200, body = req.method .. " " .. req.path }
  end
  return { status = 404, body = "no\n" }
end

return { handle = handle }
