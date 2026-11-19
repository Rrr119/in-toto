# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_multi_role_layout.py

<Purpose>
  End-to-end tests for supply chain layouts that split work across multiple
  functionary roles and require threshold signatures.

  The tests build a complete chain with the public ``runlib`` and
  ``models`` API, sign it with the project owner key and verify it with the
  unmodified ``verifylib.in_toto_verify`` entry point. In addition to the
  passing scenarios (classic Metablock and DSSE Envelope metadata), a set of
  tampering tests asserts that modifications to the layout, to link payloads
  or signatures, missing threshold evidence, unauthorized functionaries and
  disagreeing threshold links are all rejected by the existing verifier.

"""

import glob
import os
import shutil
import unittest
from pathlib import Path

from in_toto.exceptions import (
    LinkNotFoundError,
    SignatureVerificationError,
    ThresholdVerificationError,
)
from in_toto.models.layout import Inspection, Layout, Step
from in_toto.models.link import FILENAME_FORMAT
from in_toto.models.metadata import Envelope, Metablock
from in_toto.runlib import in_toto_run
from in_toto.verifylib import in_toto_verify
from tests.common import SignerStore, TmpDirMixin, VersionedPython


class MultiRoleLayoutTestCase(unittest.TestCase, TmpDirMixin):
    """Shared helpers for the multi-role threshold tests.

    The simulated supply chain has three roles:

    * ``fetch`` (threshold 1): performed by Alice (ecdsa), produces
      ``source.txt``.
    * ``build`` (threshold 1): performed by Bob (ed25519), consumes
      ``source.txt`` and produces ``artifact.bin``.
    * ``review`` (threshold 2): performed independently by Alice and Bob,
      both of which must provide validly signed link metadata recording the
      same artifacts.

    The layout itself is signed by the project owner (rsa).
    """

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

        cls.owner = SignerStore.rsa
        cls.owner_pub = SignerStore.rsa_pub
        cls.owner_keyid = cls.owner_pub["keyid"]

        cls.alice = SignerStore.ecdsa
        cls.alice_pub = SignerStore.ecdsa_pub
        cls.alice_keyid = cls.alice_pub["keyid"]

        cls.bob = SignerStore.ed25519
        cls.bob_pub = SignerStore.ed25519_pub
        cls.bob_keyid = cls.bob_pub["keyid"]

        # A harmless command available on every supported platform.
        cls.noop_cmd = [VersionedPython, "--version"]

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def setUp(self):
        # Each test gets a fresh working directory inside the class temp dir
        # so that tampering does not leak between tests.
        self.chain_dir = Path(self.test_dir) / self.id().split(".")[-1]
        self.chain_dir.mkdir()
        os.chdir(self.chain_dir)

    def tearDown(self):
        os.chdir(self.test_dir)
        shutil.rmtree(self.chain_dir)

    def _build_layout(self):
        """Returns an unsigned multi-role threshold Layout object."""
        return Layout(
            keys={
                self.alice_keyid: self.alice_pub,
                self.bob_keyid: self.bob_pub,
            },
            steps=[
                Step(
                    name="fetch",
                    pubkeys=[self.alice_keyid],
                    threshold=1,
                ),
                Step(
                    name="build",
                    pubkeys=[self.bob_keyid],
                    threshold=1,
                ),
                Step(
                    name="review",
                    pubkeys=[self.alice_keyid, self.bob_keyid],
                    threshold=2,
                ),
            ],
            inspect=[
                Inspection(name="noop", run=self.noop_cmd),
            ],
        )

    def _sign_and_dump_layout(self, layout, use_dsse=False):
        """Signs the layout with the owner key and writes root.layout."""
        if use_dsse:
            metadata = Envelope.from_signable(layout)
        else:
            metadata = Metablock(signed=layout)
        metadata.create_signature(self.owner)
        metadata.dump("root.layout")
        return metadata

    def _run_step(self, name, materials, products, signer, use_dsse=False):
        """Performs a step and writes the signed link metadata file."""
        return in_toto_run(
            name,
            materials,
            products,
            self.noop_cmd
            if name == "review"
            else [VersionedPython, "-c", "pass"],
            signer=signer,
            use_dsse=use_dsse,
        )

    def _build_supply_chain(self, use_dsse=False):
        """Creates layout, links and artifacts of a complete valid chain."""
        layout = self._build_layout()
        self._sign_and_dump_layout(layout, use_dsse=use_dsse)

        # Alice fetches the source.
        Path("source.txt").write_text("source material")
        self._run_step(
            "fetch", None, ["source.txt"], self.alice, use_dsse=use_dsse
        )

        # Bob builds the final artifact from the source.
        shutil.copy("source.txt", "artifact.bin")
        self._run_step(
            "build",
            ["source.txt"],
            ["artifact.bin"],
            self.bob,
            use_dsse=use_dsse,
        )

        # Alice and Bob independently review the result (threshold 2). Both
        # links record no artifacts, hence agree on materials and products.
        self._run_step("review", None, None, self.alice, use_dsse=use_dsse)
        self._run_step("review", None, None, self.bob, use_dsse=use_dsse)

    def _verify(self):
        """Runs the full, unmodified verifier entry point."""
        layout_metadata = Metablock.load("root.layout")
        in_toto_verify(
            layout_metadata,
            {self.owner_keyid: self.owner_pub},
        )

    def _link_path(self, step_name, keyid):
        return FILENAME_FORMAT.format(step_name=step_name, keyid=keyid)

    def test_multi_role_threshold_chain_passes(self):
        """Multi-role layout with a threshold step verifies successfully."""
        self._build_supply_chain()
        self._verify()

        # All four functionary links and the layout are present on disk.
        link_files = glob.glob("*.link")
        self.assertEqual(len(link_files), 5)
        self.assertTrue(Path("root.layout").exists())

    def test_dsse_multi_role_threshold_chain_passes(self):
        """The same chain verifies when wrapped in DSSE envelopes."""
        self._build_supply_chain(use_dsse=True)

        layout_metadata = Envelope.load("root.layout")
        in_toto_verify(
            layout_metadata,
            {self.owner_keyid: self.owner_pub},
        )

    def test_layout_requires_each_authorized_role(self):
        """Every step's authorized functionary is represented in the layout."""
        layout = self._build_layout()
        keyids = layout.get_functionary_key_id_list()
        self.assertIn(self.alice_keyid, keyids)
        self.assertIn(self.bob_keyid, keyids)

        review_step = layout.get_step_by_name("review")
        self.assertEqual(review_step.threshold, 2)
        self.assertEqual(
            set(review_step.pubkeys),
            {self.alice_keyid, self.bob_keyid},
        )

    def test_tampered_layout_signature_is_rejected(self):
        """A modified layout payload invalidates the owner signature."""
        self._build_supply_chain()

        layout_metadata = Metablock.load("root.layout")
        layout_metadata.signed.readme = "tampered layout"
        layout_metadata.dump("root.layout")

        with self.assertRaises(SignatureVerificationError):
            self._verify()

    def test_tampered_link_payload_is_rejected(self):
        """A modified link payload invalidates the functionary signature."""
        self._build_supply_chain()

        link_path = self._link_path("build", self.bob_keyid)
        link_metadata = Metablock.load(link_path)
        link_metadata.signed.command = ["tampered", "command"]
        link_metadata.dump(link_path)

        with self.assertRaises(ThresholdVerificationError):
            self._verify()

    def test_tampered_link_signature_is_rejected(self):
        """A forged link signature cannot satisfy the step threshold."""
        self._build_supply_chain()

        link_path = self._link_path("fetch", self.alice_keyid)
        link_metadata = Metablock.load(link_path)
        forged_sig = "0" * len(link_metadata.signatures[0]["sig"])
        link_metadata.signatures[0]["sig"] = forged_sig
        link_metadata.dump(link_path)

        with self.assertRaises(ThresholdVerificationError):
            self._verify()

    def test_missing_threshold_link_is_rejected(self):
        """Removing one reviewer link breaks the threshold of two."""
        self._build_supply_chain()

        os.remove(self._link_path("review", self.bob_keyid))

        with self.assertRaises((LinkNotFoundError, ThresholdVerificationError)):
            self._verify()

    def test_unauthorized_functionary_link_is_rejected(self):
        """A link signed by a key not delegated to the step is ignored."""
        self._build_supply_chain()

        # Replace Bob's build link with one signed by Alice, who is not
        # authorized for the build step.
        os.remove(self._link_path("build", self.bob_keyid))
        self._run_step(
            "build",
            ["source.txt"],
            ["artifact.bin"],
            self.alice,
        )

        with self.assertRaises((LinkNotFoundError, ThresholdVerificationError)):
            self._verify()

    def test_disagreeing_threshold_links_are_rejected(self):
        """Reviewer links with differing artifacts fail threshold constraints."""
        self._build_supply_chain()

        # Re-create Bob's review link so that it records a product Alice's
        # review link does not know about.
        os.remove(self._link_path("review", self.bob_keyid))
        Path("extra.txt").write_text("unexpected review artifact")
        in_toto_run(
            "review",
            None,
            ["extra.txt"],
            self.noop_cmd,
            signer=self.bob,
        )
        os.remove("extra.txt")

        with self.assertRaises(ThresholdVerificationError):
            self._verify()

    def test_wrong_layout_verification_key_is_rejected(self):
        """Verification fails when the owner key does not match the layout."""
        self._build_supply_chain()

        layout_metadata = Metablock.load("root.layout")
        with self.assertRaises(SignatureVerificationError):
            in_toto_verify(
                layout_metadata,
                {self.alice_keyid: self.alice_pub},
            )

    def test_dsse_tampered_link_is_rejected(self):
        """DSSE link tampering is rejected just like Metablock tampering.

        The envelope payload bytes are modified in place without re-signing,
        so the existing signature no longer matches.
        """
        self._build_supply_chain(use_dsse=True)

        link_path = self._link_path("fetch", self.alice_keyid)
        envelope = Envelope.load(link_path)
        link = envelope.get_payload()
        link.command = ["tampered", "command"]
        envelope.payload = Envelope.from_signable(link).payload
        envelope.dump(link_path)

        layout_metadata = Envelope.load("root.layout")
        with self.assertRaises(ThresholdVerificationError):
            in_toto_verify(
                layout_metadata,
                {self.owner_keyid: self.owner_pub},
            )


if __name__ == "__main__":
    unittest.main()
