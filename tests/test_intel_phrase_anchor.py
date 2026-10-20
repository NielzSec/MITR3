"""Generic adjacent phrase anchoring, independent of blind regression questions."""
import unittest
from contextlib import closing
from unittest import mock
from test_intel_routing_intent import intel, index, record


class PhraseAnchorTests(unittest.TestCase):
    def test_new_netlogon_zerologon_question(self):
        query = ('Preciso preparar uma nota técnica para manutenção sobre Microsoft Netlogon e '
                 'Zerologon; quais registros descrevem Netlogon secure channel e sua vulnerabilidade?')
        rows = intel.search(query, emit=False)
        self.assertIn('CVE-2020-1472', [r['id'] for r in rows])
        self.assertTrue(all(r.get('fallback') == 'phrase_anchor' for r in rows))

    def test_new_qnap_deadbolt_question(self):
        query = ('Para organizar uma revisão preventiva, busque referências sobre QNAP Photo Station '
                 'durante a campanha Deadbolt e informe a entrada catalogada.')
        rows = intel.search(query, emit=False)
        self.assertEqual(rows[0]['id'], 'CVE-2022-27593')
        self.assertEqual(rows[0]['fallback'], 'phrase_anchor')

    def test_new_esxiargs_vcenter_question_does_not_invent_link(self):
        query = ('Na revisão dos servidores, preciso investigar ESXiArgs e VMware vCenter Server; '
                 'quais entradas descrevem as vulnerabilidades desse componente?')
        rows = intel.search(query, emit=False)
        self.assertTrue(rows)
        self.assertTrue(all(r.get('fallback') == 'phrase_anchor' for r in rows))
        self.assertTrue(all('vcenter' in (r['title'] + r['summary']).lower() for r in rows))
        # ESXiArgs is absent in this snapshot: returning vCenter context must not
        # manufacture a campaign association, entity or source-declared edge.
        with closing(intel.open_db()) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM docs_fts WHERE docs_fts MATCH ?',
                                         ('esxiargs',)).fetchone()[0], 0)
        self.assertFalse(any('ESXiArgs' in str(r) for r in rows))

    def test_new_infostealer_family_question_abstains_before_anchor(self):
        query = ('Para uma investigação interna, qual família de infostealer usa qual CVE nas '
                 'operações documentadas e como verificar isso?')
        with mock.patch.object(intel, 'phrase_anchor', side_effect=AssertionError('intent bypass')):
            self.assertEqual(intel.search(query, emit=False), [])

    def test_nonexistent_bigram_does_not_become_anchor(self):
        with index([record('CASE-test', 'quasar separated neutrino')]):
            with closing(intel.open_db()) as con:
                self.assertEqual(intel.phrase_anchor(con, ['quasar', 'neutrino']), ())
            rows = intel.search('quasar neutrino zzqa zzqb zzqc zzqd zzqe', emit=False)
            self.assertEqual(rows[0]['fallback'], 'vocabulary')

    def test_out_of_vocabulary_word_cannot_create_adjacency(self):
        with index([record('CASE-test', 'quasar neutrino')]):
            rows = intel.search('quasar zzqa neutrino zzqb zzqc zzqd zzqe', emit=False)
            self.assertEqual(rows[0]['fallback'], 'vocabulary')

    def test_rarest_phrase_and_mandatory_phrase_per_document(self):
        records = [record('CASE-rare', 'quasar neutrino photon'),
                   record('CASE-scattered', 'quasar separated neutrino separated photon')]
        records += [record(f'CASE-common-{i}', 'plasma fusion') for i in range(3)]
        with index(records):
            tokens = 'plasma fusion zzqa quasar neutrino photon zzqb zzqc'.split()
            with closing(intel.open_db()) as con:
                self.assertEqual(intel.phrase_anchor(con, tokens), ('quasar', 'neutrino', 'photon'))
            rows = intel.search(' '.join(tokens), emit=False)
            self.assertEqual([r['id'] for r in rows], ['CASE-rare'])
            self.assertEqual(rows[0]['fallback'], 'phrase_anchor')

    def test_stopword_and_document_type_removed_before_ngrams(self):
        with index([record('CASE-test', 'quasar neutrino')]):
            rows = intel.search('zzqa quasar and report neutrino zzqb zzqc zzqd', emit=False)
            self.assertEqual(rows[0]['fallback'], 'phrase_anchor')

    def test_original_short_identifier_and_intent_paths_never_call_anchor(self):
        queries = ['cache poisoning', 'esxi encryptor', 'CVE-2020-1472',
                   'zzqa zzqb zzqc zzqd zzqe zzqf zzqg T1059.001',
                   'zzqa zzqb zzqc zzqd zzqe zzqf zzqg CVE-2020-1472']
        with mock.patch.object(intel, 'phrase_anchor', side_effect=AssertionError('guard bypass')):
            for query in queries:
                with self.subTest(query=query):
                    self.assertTrue(all('fallback' not in r for r in intel.search(query, emit=False)))

    def test_selected_anchor_does_not_bypass_explicit_source_or_kind(self):
        with index([record('CASE-test', 'quasar neutrino', 'public-cases')]):
            query = 'quasar neutrino zzqa zzqb zzqc zzqd zzqe'
            self.assertEqual(intel.search(query, source='cisa-kev', emit=False), [])
            self.assertEqual(intel.search(query, kind='nonexistent', emit=False), [])

    def test_unicode_phrase_uses_fts_tokenizer(self):
        with index([record('CASE-test', 'café neutrino')]):
            rows = intel.search('CAFÉ neutrino zzqa zzqb zzqc zzqd zzqe', emit=False)
            self.assertEqual(rows[0]['fallback'], 'phrase_anchor')
