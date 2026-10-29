/*
Copyright (c) Amazon Web Services
Distributed under the terms of the MIT license
*/

package aws_oidc_test

import (
	"os"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

var _ = Describe("Internal TLS", func() {
	var rootDir string

	BeforeEach(func() {
		var err error
		rootDir, err = filepath.Abs("../../..")
		Expect(err).NotTo(HaveOccurred())
	})

	renderInternal := func(extraArgs ...string) string {
		outputDir := GinkgoT().TempDir()
		chartDir := GinkgoT().TempDir()
		copyDir(filepath.Join(rootDir, "charts/aws-oidc"), chartDir)
		args := append(oidcRequiredArgs(), extraArgs...)
		helmTemplate(chartDir, outputDir, args...)
		return filepath.Join(outputDir, "jupyter-k8s-aws-oidc/templates")
	}

	read := func(dir, rel string) string {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		Expect(err).NotTo(HaveOccurred())
		return string(data)
	}

	on := []string{helmSetFlag, "internalTls.enabled=true"}
	off := []string{helmSetFlag, "internalTls.enabled=false"}

	It("is on for every component by default", func() {
		dir := renderInternal()
		Expect(read(dir, "dex/configmap.yaml")).To(ContainSubstring("https: 0.0.0.0:5554"))
		Expect(read(dir, "traefik/middlewares.yaml")).To(ContainSubstring("address: https://oauth2-proxy"))
		Expect(read(dir, "traefik/auth-middlewares.yaml")).To(ContainSubstring("https://authmiddleware."))
		Expect(read(dir, "web-app/ingressroute.yaml")).To(ContainSubstring("scheme: https"))
	})

	Context("disabled", func() {
		It("leaves every component on plaintext and creates no ServersTransport", func() {
			dir := renderInternal(off...)
			Expect(read(dir, "dex/configmap.yaml")).To(ContainSubstring("http: 0.0.0.0:5556"))
			Expect(read(dir, "dex/configmap.yaml")).NotTo(ContainSubstring("tlsCert"))
			Expect(read(dir, "traefik/middlewares.yaml")).To(ContainSubstring("address: http://oauth2-proxy"))
			Expect(read(dir, "traefik/auth-middlewares.yaml")).To(ContainSubstring("http://authmiddleware."))
			Expect(read(dir, authmiddlewareDeployFile)).NotTo(ContainSubstring("TLS_CERT_FILE"))
			Expect(read(dir, "web-app/deployment.yaml")).NotTo(ContainSubstring("TLS_CERT_FILE"))
			_, err := os.Stat(filepath.Join(dir, "traefik/servers-transport.yaml"))
			Expect(os.IsNotExist(err)).To(BeTrue())
			_, err = os.Stat(filepath.Join(dir, "cert-manager/certificate.yaml"))
			Expect(err).NotTo(HaveOccurred())
			Expect(read(dir, "cert-manager/certificate.yaml")).NotTo(ContainSubstring("internal-tls"))
		})
	})

	Context("enabled", func() {
		It("has dex serve HTTPS with the plaintext listener bound to localhost only", func() {
			cfg := read(renderInternal(on...), "dex/configmap.yaml")
			// Localhost, not 0.0.0.0: the probes need it, nothing on the network should.
			Expect(cfg).To(ContainSubstring("http: 127.0.0.1:5556"))
			Expect(cfg).To(ContainSubstring("https: 0.0.0.0:5554"))
			Expect(cfg).To(ContainSubstring("tlsCert: /etc/dex/tls/tls.crt"))
			// The issuer must stay the public URL — token `iss` claims and the EKS OIDC
			// provider config both depend on it.
			Expect(cfg).To(ContainSubstring("issuer: https://"))
		})

		It("probes dex over localhost rather than the TLS port", func() {
			dep := read(renderInternal(on...), "dex/deployment.yaml")
			Expect(dep).To(ContainSubstring("http://127.0.0.1:5556/dex/healthz"))
			Expect(dep).To(ContainSubstring("containerPort: 5554"))
			Expect(dep).To(ContainSubstring("secretName: dex-internal-tls"))
		})

		It("drops oauth2-proxy's plaintext listener and probes it over HTTPS", func() {
			// The image is distroless, so exec probes are impossible; that forces
			// scheme: HTTPS, which in turn leaves the HTTP listener with nothing to serve.
			dep := read(renderInternal(on...), oauth2ProxyDeployFile)
			Expect(dep).To(ContainSubstring("--https-address=0.0.0.0:4443"))
			Expect(dep).To(ContainSubstring("--http-address="))
			Expect(dep).NotTo(ContainSubstring("--http-address=0.0.0.0:4180"))
			Expect(dep).To(ContainSubstring("scheme: HTTPS"))
		})

		It("pins serverName on the IngressRoute path but not on ForwardAuth", func() {
			dir := renderInternal(on...)

			// IngressRoute services resolve to pod IPs, so serverName is mandatory —
			// without it the handshake targets an IP no SAN matches and every request 502s.
			transports := read(dir, "traefik/servers-transport.yaml")
			Expect(transports).To(ContainSubstring("serverName: dex."))
			Expect(transports).To(ContainSubstring("serverName: oauth2-proxy."))
			Expect(transports).To(ContainSubstring("insecureSkipVerify: false"))

			// ForwardAuth takes SNI from the URL hostname, so it needs a CA but no serverName.
			mw := read(dir, "traefik/middlewares.yaml")
			Expect(mw).To(ContainSubstring("caSecret: oauth2-proxy-internal-tls"))
			Expect(mw).NotTo(ContainSubstring("serverName:"))
		})

		It("gives each certificate every hostname form Traefik dials", func() {
			// The two oauth2-proxy ForwardAuth middlewares use DIFFERENT name forms: one the
			// FQDN, one the short form. A cert with only the FQDN passes /oauth2/auth and
			// fails every login redirect.
			certs := read(renderInternal(on...), "cert-manager/certificate.yaml")
			for _, name := range []string{
				"- oauth2-proxy\n", "- oauth2-proxy.jupyter-k8s-router\n",
				"- oauth2-proxy.jupyter-k8s-router.svc.cluster.local\n",
				"- dex\n", "- dex.jupyter-k8s-router\n",
				"- dex.jupyter-k8s-router.svc.cluster.local\n",
			} {
				Expect(certs).To(ContainSubstring(name))
			}
		})

		It("moves the NetworkPolicy ports along with the listeners", func() {
			dir := renderInternal(on...)
			// A netpol left on the old port silently blocks the new one.
			Expect(read(dir, "dex/network-policy.yaml")).To(ContainSubstring("port: 5554"))
			Expect(read(dir, "dex/network-policy.yaml")).NotTo(ContainSubstring("port: 5556"))
			Expect(read(dir, "oauth2-proxy/network-policy.yaml")).To(ContainSubstring("port: 4443"))
			Expect(read(dir, "authmiddleware/network-policy.yaml")).To(ContainSubstring("port: 5554"))
		})

		It("keeps the dex wait gates pointing at the port dex actually serves", func() {
			// A TCP connect, not an HTTPS GET: busybox wget offers TLS 1.2 at most, so against
			// dex's TLS 1.3-only listener it never succeeds and every gate runs to its timeout.
			// Each attempt is bounded by `timeout`: one nc that never returns would otherwise
			// stall the gate's counter, and with it the overall timeout.
			for _, args := range [][]string{on, off} {
				dir := renderInternal(args...)
				port := "5554"
				if args[1] == off[1] {
					port = "5556"
				}
				for _, f := range []string{oauth2ProxyDeployFile, authmiddlewareDeployFile} {
					body := read(dir, f)
					Expect(body).To(ContainSubstring("until timeout 5 nc -w 3 dex.jupyter-k8s-router "+port+" "), f)
					Expect(body).NotTo(ContainSubstring("until wget"), f)
				}
			}
		})

		It("keeps authmiddleware on plaintext when internalTls.authmiddleware is false", func() {
			dir := renderInternal(append(append([]string{}, on...), helmSetFlag, "internalTls.authmiddleware=false")...)
			Expect(read(dir, authmiddlewareDeployFile)).NotTo(ContainSubstring("TLS_CERT_FILE"))
			am := read(dir, "traefik/auth-middlewares.yaml")
			Expect(am).To(ContainSubstring("http://authmiddleware."))
			Expect(am).NotTo(ContainSubstring("caSecret: authmiddleware-internal-tls"))
			Expect(read(dir, "cert-manager/certificate.yaml")).NotTo(ContainSubstring("authmiddleware-internal-tls"))
		})

		It("keeps the web app on plaintext when internalTls.webApp is false", func() {
			dir := renderInternal(append(append([]string{}, on...), helmSetFlag, "internalTls.webApp=false")...)
			Expect(read(dir, "web-app/deployment.yaml")).NotTo(ContainSubstring("TLS_CERT_FILE"))
			Expect(read(dir, "web-app/ingressroute.yaml")).NotTo(ContainSubstring("scheme: https"))
			Expect(read(dir, "traefik/servers-transport.yaml")).NotTo(ContainSubstring("internal-web-app"))
		})

		It("serves dex and oauth2-proxy over TLS 1.3 only", func() {
			// Dex ignores unknown keys, so a misspelt key would silently allow TLS 1.2.
			dir := renderInternal(on...)
			Expect(read(dir, "dex/configmap.yaml")).To(ContainSubstring(`tlsMinVersion: "1.3"`))
			Expect(read(dir, oauth2ProxyDeployFile)).To(ContainSubstring("--tls-min-version=TLS1.3"))
		})

		It("exposes the TLS port on each Service", func() {
			dir := renderInternal(on...)
			for rel, want := range map[string]int32{
				"dex/service.yaml":          5554,
				"oauth2-proxy/service.yaml": 4443,
			} {
				var svc corev1.Service
				Expect(yaml.Unmarshal([]byte(read(dir, rel)), &svc)).To(Succeed())
				Expect(svc.Spec.Ports).To(HaveLen(1), rel)
				Expect(svc.Spec.Ports[0].Port).To(Equal(want), rel)
				Expect(svc.Spec.Ports[0].Name).To(Equal("https"), rel)
			}
		})
	})

	Context("enabled for the web app", func() {
		webApp := on // internalTls.webApp defaults to true

		It("serves HTTPS from a whole-volume Secret mount so a renewed certificate is picked up", func() {
			// The server re-reads the files on a poll; the kubelet only updates a Secret
			// volume mounted whole, never a subPath mount.
			var d appsv1.Deployment
			Expect(yaml.Unmarshal([]byte(read(renderInternal(webApp...), "web-app/deployment.yaml")), &d)).To(Succeed())
			c := d.Spec.Template.Spec.Containers[0]
			env := map[string]string{}
			for _, e := range c.Env {
				env[e.Name] = e.Value
			}
			Expect(env).To(HaveKeyWithValue("TLS_CERT_FILE", "/etc/web-app/tls/tls.crt"))
			Expect(env).To(HaveKeyWithValue("TLS_KEY_FILE", "/etc/web-app/tls/tls.key"))
			Expect(env).To(HaveKeyWithValue("PORT", "8443"))
			Expect(c.VolumeMounts).To(HaveLen(1))
			Expect(c.VolumeMounts[0].MountPath).To(Equal("/etc/web-app/tls"))
			Expect(c.VolumeMounts[0].SubPath).To(BeEmpty())
			vols := d.Spec.Template.Spec.Volumes
			Expect(vols).To(HaveLen(1))
			Expect(vols[0].Secret.SecretName).To(Equal("web-app-internal-tls"))
		})

		It("probes the TLS port over HTTPS", func() {
			var d appsv1.Deployment
			Expect(yaml.Unmarshal([]byte(read(renderInternal(webApp...), "web-app/deployment.yaml")), &d)).To(Succeed())
			c := d.Spec.Template.Spec.Containers[0]
			for _, p := range []*corev1.Probe{c.LivenessProbe, c.ReadinessProbe} {
				Expect(p.HTTPGet.Scheme).To(Equal(corev1.URISchemeHTTPS))
				Expect(p.HTTPGet.Port.String()).To(Equal("https"))
			}
			Expect(c.Ports).To(HaveLen(1))
			Expect(c.Ports[0].Name).To(Equal("https"))
			Expect(c.Ports[0].ContainerPort).To(Equal(int32(8443)))
		})

		It("routes every web-app IngressRoute over HTTPS through the pinned ServersTransport", func() {
			dir := renderInternal(webApp...)
			// Three routes (session fast path, auth path, SPA catch-all); one left on
			// plaintext would 502 on that path only.
			routes := read(dir, "web-app/ingressroute.yaml")
			Expect(strings.Count(routes, "port: 8443")).To(Equal(3))
			Expect(strings.Count(routes, "scheme: https")).To(Equal(3))
			Expect(strings.Count(routes, "serversTransport: internal-web-app")).To(Equal(3))
			Expect(routes).NotTo(ContainSubstring("8090"))

			transports := read(dir, "traefik/servers-transport.yaml")
			Expect(transports).To(ContainSubstring("serverName: web-app.jupyter-k8s-router.svc.cluster.local"))
			Expect(transports).To(ContainSubstring("- web-app-internal-tls"))

			certs := read(dir, "cert-manager/certificate.yaml")
			Expect(certs).To(ContainSubstring("- web-app.jupyter-k8s-router.svc.cluster.local\n"))
		})

		It("moves the Service and NetworkPolicy to the TLS port", func() {
			dir := renderInternal(webApp...)
			var svc corev1.Service
			Expect(yaml.Unmarshal([]byte(read(dir, "web-app/service.yaml")), &svc)).To(Succeed())
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(8443)))
			Expect(svc.Spec.Ports[0].Name).To(Equal("https"))

			np := read(dir, "web-app/network-policy.yaml")
			Expect(np).To(ContainSubstring("port: 8443"))
			Expect(np).NotTo(ContainSubstring("port: 8090"))
		})
	})

	Context("enabled for authmiddleware", func() {
		authmiddleware := on // internalTls.authmiddleware defaults to true

		It("serves HTTPS from a whole-volume Secret mount so a renewed certificate is picked up", func() {
			// The server watches the files; the kubelet only updates a Secret volume
			// mounted whole, never a subPath mount.
			var d appsv1.Deployment
			Expect(yaml.Unmarshal([]byte(read(renderInternal(authmiddleware...), authmiddlewareDeployFile)), &d)).To(Succeed())
			c := d.Spec.Template.Spec.Containers[0]
			env := map[string]string{}
			for _, e := range c.Env {
				env[e.Name] = e.Value
			}
			Expect(env).To(HaveKeyWithValue("TLS_CERT_FILE", "/etc/authmiddleware/tls/tls.crt"))
			Expect(env).To(HaveKeyWithValue("TLS_KEY_FILE", "/etc/authmiddleware/tls/tls.key"))
			Expect(env).To(HaveKeyWithValue("PORT", "8443"))

			var mount *corev1.VolumeMount
			for i := range c.VolumeMounts {
				if c.VolumeMounts[i].Name == "internal-tls" {
					mount = &c.VolumeMounts[i]
				}
			}
			Expect(mount).NotTo(BeNil())
			Expect(mount.MountPath).To(Equal("/etc/authmiddleware/tls"))
			Expect(mount.SubPath).To(BeEmpty())

			var secret string
			for _, v := range d.Spec.Template.Spec.Volumes {
				if v.Name == "internal-tls" {
					secret = v.Secret.SecretName
				}
			}
			Expect(secret).To(Equal("authmiddleware-internal-tls"))
		})

		It("probes the TLS port over HTTPS", func() {
			// Plain HTTP gets a 400 once TLS is on, so an HTTP probe would never pass.
			var d appsv1.Deployment
			Expect(yaml.Unmarshal([]byte(read(renderInternal(authmiddleware...), authmiddlewareDeployFile)), &d)).To(Succeed())
			c := d.Spec.Template.Spec.Containers[0]
			for _, p := range []*corev1.Probe{c.LivenessProbe, c.ReadinessProbe} {
				Expect(p.HTTPGet.Scheme).To(Equal(corev1.URISchemeHTTPS))
				Expect(p.HTTPGet.Port.String()).To(Equal("https"))
			}
			Expect(c.Ports).To(HaveLen(1))
			Expect(c.Ports[0].Name).To(Equal("https"))
			Expect(c.Ports[0].ContainerPort).To(Equal(int32(8443)))
		})

		It("points every ForwardAuth middleware at HTTPS with the internal CA", func() {
			// auth, verify and bearer-auth; one left on http:// would fail that path only.
			// ForwardAuth takes SNI from the URL hostname, so no ServersTransport is needed.
			dir := renderInternal(append(append([]string{}, authmiddleware...),
				helmSetFlag, "authmiddleware.enableBearerAuth=true")...)
			am := read(dir, "traefik/auth-middlewares.yaml")
			Expect(strings.Count(am, "https://authmiddleware.jupyter-k8s-router:8443/")).To(Equal(3))
			Expect(strings.Count(am, "caSecret: authmiddleware-internal-tls")).To(Equal(3))
			Expect(am).NotTo(ContainSubstring("http://authmiddleware."))
			Expect(am).NotTo(ContainSubstring(":8080"))

			Expect(read(dir, "traefik/servers-transport.yaml")).NotTo(ContainSubstring("internal-authmiddleware"))
			certs := read(dir, "cert-manager/certificate.yaml")
			Expect(certs).To(ContainSubstring("secretName: authmiddleware-internal-tls"))
			Expect(certs).To(ContainSubstring("- authmiddleware.jupyter-k8s-router\n"))
		})

		It("moves the Service and NetworkPolicy to the TLS port", func() {
			dir := renderInternal(authmiddleware...)
			var svc corev1.Service
			Expect(yaml.Unmarshal([]byte(read(dir, "authmiddleware/service.yaml")), &svc)).To(Succeed())
			Expect(svc.Spec.Ports).To(HaveLen(1))
			Expect(svc.Spec.Ports[0].Port).To(Equal(int32(8443)))
			Expect(svc.Spec.Ports[0].Name).To(Equal("https"))
			Expect(svc.Spec.Ports[0].TargetPort.String()).To(Equal("https"))

			np := read(dir, "authmiddleware/network-policy.yaml")
			Expect(np).To(ContainSubstring("port: 8443"))
			Expect(np).NotTo(ContainSubstring("port: 8080"))
		})
	})
})
