#!/usr/bin/env python3
"""Enter one contained COR24 stage with its clean caller environment, not outer fixture ownership."""
import json,os,stat,sys
from pathlib import Path
def load_environment(path):
 path=path.resolve()
 if path.is_symlink() or path.name!='cor24-stage-environment.json' or 'test-runs' not in path.parts:raise ValueError('Private stage environment required')
 if os.name!='nt' and (path.stat().st_uid!=os.getuid() or stat.S_IMODE(path.stat().st_mode)!=0o600):raise ValueError('Private owner-only stage environment required')
 data=json.loads(path.read_text())
 if not isinstance(data,dict) or any(not isinstance(k,str) or not isinstance(v,str) or '\0' in k+v or '=' in k for k,v in data.items()):raise ValueError('Invalid stage environment')
 return data
def main():
 if len(sys.argv)<3:raise ValueError('Private environment and stage argv required')
 environment=load_environment(Path(sys.argv[1]));command=sys.argv[2:]
 os.execvpe(command[0],command,environment)
if __name__=='__main__':main()
