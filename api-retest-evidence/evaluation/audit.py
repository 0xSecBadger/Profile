#!/usr/bin/env python3
"""Offline integrity checks for stored runs; does not call Ollama."""
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import evaluate as e


def main():
    corpus = json.loads((e.ROOT / 'results/corpus.json').read_text())
    gold = e.oracle_results(corpus)
    runs = sorted((e.ROOT / 'evaluation').glob('qwen3_*/summary.json'))
    assert runs, 'No completed runs found.'
    results = []
    expected_prompts = None
    forbidden = {'scenario_id', 'title', 'fault_model', 'expected', 'verdict', 'notes'}
    def inspect_keys(value):
        if isinstance(value, dict):
            assert not (forbidden & set(value)), 'Leaked metadata key'
            for item in value.values(): inspect_keys(item)
        elif isinstance(value, list):
            for item in value: inspect_keys(item)
    for path in runs:
        folder = path.parent
        metadata_path = folder / 'metadata.public.json'
        if not metadata_path.exists():
            metadata_path = folder / 'metadata.json'
        metadata = json.loads(metadata_path.read_text())
        records = [json.loads(line) for line in (folder / 'raw.jsonl').read_text().splitlines()]
        saved_summary = json.loads(path.read_text())
        assert len(records) == len(corpus) == 28
        assert metadata['endpoint'] == 'http://localhost:11434/api/chat'
        assert metadata['script_sha256'] == e.digest_bytes((e.ROOT / 'evaluation/evaluate.py').read_bytes())
        for name, expected_hash in metadata['source_sha256'].items():
            assert e.digest_bytes((e.ROOT / name).read_bytes()) == expected_hash, name
        assert metadata['system_prompt_sha256'] == e.digest_bytes(e.PROMPT.encode())
        assert metadata['schema_sha256'] == e.digest_bytes(e.canonical(e.SCHEMA).encode())
        prompts = []
        for index, (record, case, oracle) in enumerate(zip(records, corpus, gold), 1):
            assert record['index'] == index and record['scenario_id'] == case['scenario_id']
            assert record['gold'] == oracle
            request = record['request']
            assert request['model'] == metadata['model']
            assert request['options'] == e.OPTIONS and request['think'] is False and request['stream'] is False
            assert request['format'] == e.SCHEMA
            assert len(request['messages']) == 2 and request['messages'][0]['content'] == e.PROMPT
            observation = json.loads(request['messages'][1]['content'].split('\n', 1)[1])
            inspect_keys(observation)
            assert not re.search(r'S\d{2}', e.canonical(observation)), 'Scenario identifier leaked'
            assert observation == e.blinded_observation(case)
            assert record['diagnostic_gold'] == e.diagnostic_gold(observation)
            assert record['request_sha256'] == e.digest_bytes(e.canonical(request).encode())
            assert record['prompt_sha256'] == e.digest_bytes(e.canonical(request['messages']).encode())
            if record['prediction'] in e.LABELS:
                assert record['parsed'] == json.loads(record['raw_response']['message']['content'])
                assert not e.validate_output(record['parsed'])
                assert record['parsed']['verdict'] == record['prediction']
            prompts.append(record['prompt_sha256'])
        recalculated = e.summarize(records)
        assert all(saved_summary[key] == value for key, value in recalculated.items()), 'Summary mismatch'
        if expected_prompts is None: expected_prompts = prompts
        else: assert prompts == expected_prompts, 'Models did not receive identical prompts'
        results.append({'run': folder.name, 'records': len(records), 'checks_passed': True,
                        'raw_sha256': e.digest_bytes((folder / 'raw.jsonl').read_bytes()),
                        'metadata_file': metadata_path.name,
                        'metadata_sha256': e.digest_bytes(metadata_path.read_bytes()),
                        'summary_sha256': e.digest_bytes(path.read_bytes())})
    report = {'audited_at_utc': e.utc_now(), 'offline_only': True, 'runs': results,
              'checks': ['28 records in original order', 'fresh oracle matches logged gold',
                         'engine sources and corpus hashes unchanged', 'script and prompt hashes match',
                         'observation metadata absent and scenario IDs pseudonymized',
                         'identical prompt per scenario across models', 'raw JSON parses to recorded prediction',
                         'diagnostic labels and all metrics recalculate exactly']}
    (e.ROOT / 'evaluation/audit-results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
