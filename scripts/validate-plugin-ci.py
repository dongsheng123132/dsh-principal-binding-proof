import json
from pathlib import Path
root = Path(__file__).resolve().parents[1]
data = json.loads((root / '.codex-plugin' / 'plugin.json').read_text(encoding='utf-8'))
assert data['name'] == root.name
assert data['mcpServers'] == './.mcp.json'
assert not list(root.rglob('*TODO*'))
print('portable plugin manifest validation ok')
