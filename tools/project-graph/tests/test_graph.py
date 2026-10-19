import unittest

from pgraph.graph import Graph, GraphError, load_graph, validate_graph

import support


def _real():
    return load_graph(support.trusted_text())


def _codes(errors):
    return {e.split(":", 1)[0] for e in errors}


class LoadTests(unittest.TestCase):

    def test_real_graph_loads(self):
        self.assertEqual(_real()["schema"], "retail-tower/project-graph@1")

    def test_rejects_aliases_anchors_duplicates_and_oversize(self):
        bad = {
            "alias": "a: &x 1\nb: *x\n",
            "duplicate": "a: 1\na: 2\n",
            "not-a-mapping": "- 1\n- 2\n",
            "syntax": "a: [\n",
            "oversize": "a: '" + "x" * 300_000 + "'\n",
            "python-tag": "a: !!python/object:os.system x\n",
        }
        for name, text in bad.items():
            with self.subTest(name=name):
                with self.assertRaises(GraphError):
                    load_graph(text)


class StaticRuleTests(unittest.TestCase):

    def test_real_graph_valid_when_all_jobs_exist(self):
        g = _real()
        self.assertEqual(validate_graph(g, workflow_jobs=dict(g["jobs"])), [])

    def test_rule1_overlapping_product_roots(self):
        g = _real()
        g["products"]["admin-console"]["root"] = "apps/pos/admin/"
        self.assertIn("ROOT_OVERLAP", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_rule2_shared_glob_inside_product_root(self):
        g = _real()
        g["shared_classes"]["tooling"]["globs"].append("apps/pos/tools/**")
        self.assertIn("SHARED_GLOB_IN_PRODUCT", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_rule2_unanchored_shared_glob(self):
        g = _real()
        g["shared_classes"]["docs"]["globs"].append("**/README.md")
        self.assertIn("SHARED_GLOB_IN_PRODUCT", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_rule3_tier_glob_escaping_product(self):
        g = _real()
        g["products"]["pos"]["tiers"]["money"]["globs"].append("../backend-core/x")
        self.assertIn("TIER_GLOB_OUTSIDE_PRODUCT", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_rule4_missing_lockfile_and_via_at_head(self):
        g = _real()
        tree = {"apps/pos/package-lock.json"}
        codes = _codes(validate_graph(g, tree_paths=tree, workflow_jobs=dict(g["jobs"])))
        self.assertIn("LOCKFILE_MISSING", codes)
        self.assertIn("EDGE_VIA_MISSING", codes)
        self.assertIn("GENERATED_PATH_MISSING", codes)

    def test_rule5_job_missing_from_workflow(self):
        g = _real()
        jobs = dict(g["jobs"])
        del jobs["pos/static"]
        errors = validate_graph(g, workflow_jobs=jobs)
        self.assertIn("CI_JOB_MISSING: pos/static", errors)

    def test_rule5_unknown_job_reference(self):
        g = _real()
        g["products"]["pos"]["tiers"]["money"]["jobs"].append("pos/nope")
        self.assertIn("UNKNOWN_JOB", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_rule5_job_owned_by_two_products(self):
        g = _real()
        g["products"]["admin-console"]["ci_jobs"].append("pos/static")
        self.assertIn("DUPLICATE_JOB", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_rule6_same_precedence_overlap(self):
        g = _real()
        g["shared_classes"]["docs"]["globs"].append("tests/e2e/docs/**")
        self.assertIn("SAME_PRECEDENCE_OVERLAP", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))

    def test_schema_errors(self):
        g = _real()
        g["schema"] = "other@2"
        self.assertIn("SCHEMA", _codes(validate_graph(g, workflow_jobs=dict(g["jobs"]))))
        g = _real()
        del g["products"]
        self.assertIn("SCHEMA", _codes(validate_graph(g)))

    def test_proposed_graph_with_extra_approver_still_validates(self):
        g = _real()
        g["policy_approvers"] = ["someone"]
        self.assertEqual(validate_graph(g, workflow_jobs=dict(g["jobs"])), [])


class ClassifyTests(unittest.TestCase):

    def setUp(self):
        self.g = Graph(_real())

    def test_shared_precedence(self):
        self.assertEqual(self.g.classify("CODEOWNERS").owner, "policy")
        self.assertEqual(self.g.classify("tools/project-graph/x").owner, "policy")
        self.assertEqual(self.g.classify("tools/agent-broker/broker.py").owner, "policy")
        self.assertEqual(self.g.classify("tools/history/frozen.tsv").owner, "tooling")
        self.assertEqual(self.g.classify("LICENSE").owner, "root")
        self.assertEqual(self.g.classify("docs/a.md").owner, "docs")

    def test_product_tiers(self):
        c = self.g.classify("apps/pos/src/main/payments/a.ts")
        self.assertEqual((c.kind, c.owner, set(c.tiers)), ("product", "pos", {"money"}))
        c = self.g.classify("apps/pos/electron-builder.yml")
        self.assertEqual(set(c.tiers), {"electron-security", "windows-packaging"})

    def test_low_dropped_when_another_tier_matches(self):
        data = _real()
        data["products"]["pos"]["tiers"]["low"]["globs"].append("src/main/payments/**")
        c = Graph(data).classify("apps/pos/src/main/payments/a.ts")
        self.assertEqual(set(c.tiers), {"money"})

    def test_bc_docs_are_high_until_quoted_literal_rule_exists(self):
        self.assertEqual(self.g.classify("services/backend-core/deploy/README.md").tiers, ("deploy-security",))
        self.assertEqual(self.g.classify("services/backend-core/docs/guide.md").tiers, ("high",))

    def test_exclude_removes_a_tier_match(self):
        data = _real()
        data["products"]["pos"]["tiers"]["low"]["exclude"] = ["docs/**/*.sql"]
        g = Graph(data)
        self.assertEqual(g.classify("apps/pos/docs/a.md").tiers, ("low",))
        self.assertEqual(g.classify("apps/pos/docs/a.sql").tiers, ("high",))

    def test_unknown(self):
        self.assertEqual(self.g.classify("foo/x").kind, "unknown")

    def test_ambiguous_same_precedence(self):
        data = _real()
        data["shared_classes"]["e2e"]["globs"].append("docs/**")
        self.assertEqual(Graph(data).classify("docs/a.md").kind, "ambiguous")


if __name__ == "__main__":
    unittest.main()
