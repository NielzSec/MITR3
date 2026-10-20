"""Vocabulary fallback: independent questions and synthetic lexical contracts.

No blind dataset is loaded or used to construct these tests.
"""
import unittest
from unittest import mock
from test_intel_routing_intent import intel, index, record


class VocabularyTests(unittest.TestCase):
    def test_new_cobalt_question(self):
        query = ("Você pode detalhar a vulnerabilidade Cobalt Strike Teamserver Beacon configuration "
                 "para nossa avaliação preventiva, considerando somente os registros oficiais "
                 "e as atualizações recomendadas pelo fornecedor?")
        rows = intel.search(query, emit=False)
        self.assertTrue({r['id'] for r in rows} & {'CVE-2022-39197', 'CVE-2022-42948'})
        self.assertTrue(all(r['fallback'] == 'phrase_anchor' for r in rows))

    def test_new_netlogon_question(self):
        query = ("Você pode explicar a vulnerabilidade Netlogon MS-NRPC secure channel para nossa "
                 "verificação defensiva, considerando somente a documentação e as atualizações "
                 "recomendadas pelo fornecedor?")
        self.assertIn('CVE-2020-1472', [r['id'] for r in intel.search(query, emit=False)])

    def test_family_actor_attribution_never_falls_back(self):
        queries = (
            'Durante nossa revisão defensiva, qual familia de infostealer usa CVE para comprometer sistemas?',
            'Which malware family uses vulnerabilities during the intrusions that we are investigating?',
            'Which actor uses the vulnerability described in the report for our investigation?',
            'Who is responsible for attribution of this ransomware campaign during our investigation?',
        )
        with mock.patch.object(intel, 'vocabulary_terms', side_effect=AssertionError('intent bypass')):
            for query in queries:
                with self.subTest(query=query):
                    self.assertIsNotNone(intel.is_unsupported_intent(query))
                    self.assertEqual(intel.search(query, emit=False), [])

    def test_oov_removed_and_fts_normalization_used(self):
        with index([record('CASE-test', 'Café separated alpha')]):
            rows = intel.search('CAFÉ alpha zzqa zzqb zzqc zzqd zzqe zzqf', emit=False)
            self.assertEqual([r['id'] for r in rows], ['CASE-test'])
            self.assertEqual(rows[0]['fallback'], 'vocabulary')

    def test_rare_three_requires_two_not_one(self):
        records = [record('CASE-pair', 'beta separated alpha'), record('CASE-single', 'gamma')]
        records += [record(f'CASE-common-{i}', 'common delta epsilon zeta') for i in range(3)]
        with index(records):
            rows = intel.search('alpha gamma delta beta epsilon common zeta', emit=False)
            self.assertEqual([r['id'] for r in rows], ['CASE-pair'])
            self.assertEqual(rows[0]['fallback'], 'vocabulary_rare')

    def test_present_terms_still_need_sixty_percent(self):
        with index([record('CASE-pair', 'beta separated alpha'), record('CASE-other', 'delta separated gamma')]):
            rows = intel.search('alpha beta gamma delta zzqa zzqb zzqc', emit=False)
            # Four present terms require three; neither pair satisfies it.
            self.assertEqual([r['id'] for r in rows], ['CASE-pair'])
            self.assertEqual(rows[0]['fallback'], 'vocabulary_rare')

    def test_all_oov_abstains(self):
        with index([record('CASE-test', 'alpha beta')]):
            self.assertEqual(intel.search('zzqa zzqb zzqc zzqd zzqe zzqf zzqg', emit=False), [])

    def test_short_queries_unchanged(self):
        with mock.patch.object(intel, 'vocabulary_terms', side_effect=AssertionError('short relaxed')):
            self.assertEqual([r['id'] for r in intel.search('cache poisoning', emit=False)],
                             ['CASE-ps-practical-cache-poisoning-2018', 'CASE-ps-cache-2024'])
            self.assertEqual(intel.search('esxi encryptor', emit=False), [])
            with index([record('CASE-test', 'alpha beta')]):
                self.assertEqual(intel.search('alpha zzqa zzqb', emit=False), [])
                self.assertEqual(intel.search('alpha beta zzqa zzqb zzqc zzqd', emit=False), [])

    def test_identifiers_anywhere_prevent_relaxation(self):
        with index([record('CASE-test', 'alpha beta')]):
            with mock.patch.object(intel, 'vocabulary_terms', side_effect=AssertionError('ID relaxed')):
                for identifier in ('CVE-2020-1472', 'CWE-79', 'ASVS-V1.2.3', 'T1059', 'T1059.001'):
                    with self.subTest(identifier=identifier):
                        query = ' '.join(['zzqa'] * 16 + ['alpha', 'beta', identifier])
                        self.assertEqual(intel.search(query, emit=False), [])

    def test_exact_cve_unchanged(self):
        with mock.patch.object(intel, 'vocabulary_terms', side_effect=AssertionError('exact relaxed')):
            rows = intel.search('CVE-2020-1472', emit=False)
            self.assertEqual([r['id'] for r in rows], ['CVE-2020-1472'])
            self.assertNotIn('fallback', rows[0])
            self.assertEqual(intel.search('CVE-2099-999999', emit=False), [])

    def test_terms_after_original_fifteen_used(self):
        with index([record('CASE-test', 'alpha beta')]):
            query = ' '.join(['zzqa'] * 16 + ['alpha', 'beta'])
            self.assertEqual(intel.search(query, emit=False)[0]['fallback'], 'phrase_anchor')

    def test_explicit_filters_respected(self):
        records = [record('CASE-a', 'alpha beta', 'public-cases'),
                   record('CASE-b', 'alpha beta', 'cisa-kev')]
        with index(records):
            query = 'alpha beta zzqa zzqb zzqc zzqd zzqe'
            rows = intel.search(query, source='cisa-kev', emit=False)
            self.assertEqual([r['id'] for r in rows], ['CASE-b'])
            self.assertEqual(intel.search(query, kind='nonexistent', emit=False), [])

    def test_successful_first_pass_never_uses_fallback(self):
        with index([record('CASE-test', 'alpha beta gamma delta epsilon zeta eta')]):
            with mock.patch.object(intel, 'vocabulary_terms', side_effect=AssertionError('unnecessary fallback')):
                rows = intel.search('alpha beta gamma delta epsilon zeta eta', emit=False)
                self.assertEqual([r['id'] for r in rows], ['CASE-test'])
                self.assertNotIn('fallback', rows[0])
