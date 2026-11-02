#!/usr/bin/env python3
"""Supplemental lexical scope guard, never native reader/transaction evidence."""
import argparse
import re
from pathlib import Path

METHODS = ('PlaceActivation', 'CancelActivationRequest', 'DisableActivation', 'VerifyActivation', 'AdmitCreationAsync', 'TransitionAsync')


def mask(source):
    # Mask literals/comments while retaining offsets and structural braces.
    pattern = r'"""[\s\S]*?"""|@"(?:""|[^"])*"|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: re.sub(r'[^\n]', ' ', m[0]), source)


def closing(text, start, left='{', right='}'):
    depth = 0
    for n in range(start, len(text)):
        if text[n] == left: depth += 1
        if text[n] == right:
            depth -= 1
            if depth == 0: return n
    raise ValueError('Unbalanced source scope')


def validate_method(source, method):
    text = mask(source)
    signatures = list(re.finditer(r'\bpublic\s+(?:async\s+)?[\w<>?,.]+\s+'+re.escape(method)+r'\s*\(', text))
    if len(signatures) != 1: raise ValueError('Missing/ambiguous method: '+method)
    start = text.index('{', closing(text, signatures[0].end()-1, '(', ')'))
    end = closing(text, start)
    body = text[start:end+1]
    scopes = []
    for using in re.finditer(r'\bawait\s+using\s*\(', body):
        paren = using.end()-1
        last = closing(body, paren, '(', ')')
        if 'ExecuteReaderAsync' not in body[paren:last]: continue
        brace = last+1
        while body[brace].isspace(): brace += 1
        if body[brace] != '{': raise ValueError('Reader needs a nested owned scope: '+method)
        scopes.append((brace, closing(body, brace)))
    commits = list(re.finditer(r'\b\w+\.CommitAsync\s*\(', body))
    if len(scopes) != 1 or len(re.findall(r'\bExecuteReaderAsync\s*\(', body)) != 1 or len(commits) != 1:
        raise ValueError('Unreconciled reader/commit shape: '+method)
    reader_start, reader_end = scopes[0]
    if commits[0].start() <= reader_end:
        raise ValueError('Receipt/commit occurs before reader scope is closed: '+method)
    if not re.search(r'\b(?:result\s*=|ReadAsync\s*\()', body[reader_start:reader_end]):
        raise ValueError('Result must materialize within the owned reader scope')
    return method


def validate(root):
    source = (root/'Repos/ActivationRepo.cs').read_text()
    return [validate_method(source, method) for method in METHODS]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    args=p.parse_args()
    try:
        methods=validate(args.root)
        print('Lexical reader scopes agree for '+str(len(methods))+' activation methods; native qualification remains pending.')
        return 0
    except (ValueError,OSError) as e:
        print(str(e));return 1


if __name__=='__main__': raise SystemExit(main())
