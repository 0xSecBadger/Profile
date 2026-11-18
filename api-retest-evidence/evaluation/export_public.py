#!/usr/bin/env python3
"""Export this evaluation with complete prompts/responses, omitting local model paths."""
import copy
import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALUATION = ROOT / 'evaluation'


def main():
    bundle = EVALUATION / 'public_bundle'
    if bundle.exists():
        raise SystemExit('Refusing to overwrite existing public_bundle; choose a clean export directory.')
    bundle.mkdir()
    sources = ['src/retest_lab/__init__.py', 'src/retest_lab/model.py', 'src/retest_lab/verifier.py',
               'results/corpus.json', 'results/report.json', 'evaluation/evaluate.py',
               'evaluation/audit.py', 'evaluation/export_public.py', 'evaluation/README.md']
    for source in sources:
        target = bundle / source
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / source, target)
    for summary in sorted(EVALUATION.glob('qwen3_*/summary.json')):
        run = summary.parent
        metadata_path = run / 'metadata.json'
        if not metadata_path.exists():
            metadata_path = run / 'metadata.public.json'
        metadata = json.loads(metadata_path.read_text())
        public = copy.deepcopy(metadata)
        public['model_show'].pop('modelfile', None)
        public['publication_redaction'] = {
            'omitted_field': 'model_show.modelfile',
            'reason': 'Generated Modelfile includes an irrelevant local filesystem path to the installed model blob.',
            'full_local_metadata_retained': True,
            'model_identity_unchanged': True,
        }
        public_text = json.dumps(public, indent=2) + '\n'
        assert '/Users/' not in public_text and '/home/' not in public_text
        (run / 'metadata.public.json').write_text(public_text)
        target = bundle / 'evaluation' / run.name
        target.mkdir(parents=True)
        (target / 'metadata.public.json').write_text(public_text)
        for name in ['raw.jsonl', 'summary.json']:
            shutil.copy2(run / name, target / name)
    files = sorted(path for path in bundle.rglob('*') if path.is_file())
    manifest = {'scope': 'Evaluation-only reproducible public export; not the complete parent project.',
                'redaction': 'Only model_show.modelfile omitted from metadata; full requests and raw responses retained.',
                'sha256': {str(path.relative_to(bundle)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}}
    for path in files:
        text = path.read_text()
        # Do not expose a real home directory through any published artifact.
        assert not re.search(r'/(?:Users|home)/[A-Za-z0-9_-]+/', text), str(path)
    manifest_text = json.dumps(manifest, indent=2) + '\n'
    (bundle / 'PUBLIC-MANIFEST.json').write_text(manifest_text)
    (EVALUATION / 'public-manifest.json').write_text(manifest_text)
    archive = EVALUATION / 'local-model-evaluation-public.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as out:
        for path in sorted(p for p in bundle.rglob('*') if p.is_file()):
            out.write(path, path.relative_to(bundle))
    print(json.dumps({'archive': str(archive.relative_to(ROOT)), 'files': len(files) + 1,
                      'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}, indent=2))


if __name__ == '__main__':
    main()
