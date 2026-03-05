# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

- Add McpTool interface and McpToolRegistry for defining and registering tools
- Add MCP JSON-RPC endpoints: initialize, ping, tools/list, tools/call
- Add zap_version and zap_info tools
- Add zap://history/{id} resource for full HTTP request/response by history ID
- Add historyRef field to alerts linking to zap://history/{id}
- Change zap://history to return summary (count) instead of full list
- Add zap://sites-tree resource (Sites Tree format as JSON)
- Add option to record MCP requests in ZAP history (disabled by default)
