/*
Copyright (c) Amazon Web Services
Distributed under the terms of the MIT license
*/

package aws_oidc_test

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
)

var _ = Describe("OAuth2 Proxy", func() {
	Context("network policy", func() {
		var np networkingv1.NetworkPolicy

		BeforeEach(func() {
			rootDir, err := filepath.Abs("../../..")
			Expect(err).NotTo(HaveOccurred())
			np = renderNetworkPolicy(rootDir, "oauth2-proxy/network-policy.yaml")
		})

		It("should allow :443 egress for Dex via the public domain", func() {
			Expect(egressPorts(np)).To(HaveKey(443), "oauth2-proxy needs :443 egress to reach Dex via the public domain")
		})

		// oauth2-proxy's wait-for-dex initContainer connects to
		// dex.<ns>:5554 (internalTls is on by default). That
		// egress must be scoped to the dex pods in this namespace, not left open.
		It("should scope :5554 egress to dex pods in this namespace", func() {
			Expect(egressScopedToPodOnPort(np, 5554, "dex")).To(BeTrue(),
				":5554 egress should target dex pods, namespace-scoped")
		})

		// :80 plaintext egress was unused boilerplate (issuer/redirect are https,
		// upstream is static://); dropping it removes needless attack surface.
		It("should not allow unused :80 plaintext egress", func() {
			Expect(egressPorts(np)).NotTo(HaveKey(80), "oauth2-proxy makes no plaintext :80 egress; the rule should be removed")
		})
	})
})
