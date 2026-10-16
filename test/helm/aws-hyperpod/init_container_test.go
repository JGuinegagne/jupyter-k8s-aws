/*
Copyright (c) Amazon Web Services
Distributed under the terms of the MIT license
*/

package aws_hyperpod_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"sigs.k8s.io/yaml"
)

// accessStrategy mirrors the subset of WorkspaceAccessStrategy's spec this suite cares about.
type accessStrategy struct {
	Spec struct {
		DeploymentModifications struct {
			PodModifications struct {
				Volumes                       []map[string]interface{} `json:"volumes"`
				InitContainers                []map[string]interface{} `json:"initContainers"`
				PrimaryContainerModifications struct {
					VolumeMounts []map[string]interface{} `json:"volumeMounts"`
				} `json:"primaryContainerModifications"`
			} `json:"podModifications"`
		} `json:"deploymentModifications"`
	} `json:"spec"`
}

func renderAccessStrategy(chartDir string, extraArgs ...string) (accessStrategy, error) {
	args := append([]string{
		"template", "init-container-test", chartDir,
		"-s", "templates/hyperpod-access-strategy.yaml",
	}, extraArgs...)

	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		return accessStrategy{}, fmt.Errorf("helm template failed: %w\n%s", err, out)
	}

	var strategy accessStrategy
	if err := yaml.Unmarshal(out, &strategy); err != nil {
		return accessStrategy{}, fmt.Errorf("failed to unmarshal rendered access strategy: %w", err)
	}
	return strategy, nil
}

// Helm refuses to template a chart whose declared dependencies (traefik) aren't
// vendored under charts/, so build a throwaway copy with dependencies resolved
// once for the whole suite instead of per spec.
var builtChartDir string

var _ = BeforeSuite(func() {
	rootDir, err := filepath.Abs("../../..")
	Expect(err).NotTo(HaveOccurred())

	tmpDir, err := os.MkdirTemp("", "aws-hyperpod-chart-*")
	Expect(err).NotTo(HaveOccurred())
	builtChartDir = filepath.Join(tmpDir, "aws-hyperpod")

	out, err := exec.Command("cp", "-r", filepath.Join(rootDir, "charts", "aws-hyperpod"), builtChartDir).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))

	out, err = exec.Command("helm", "dependency", "build", builtChartDir).CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), string(out))
})

var _ = AfterSuite(func() {
	if builtChartDir != "" {
		Expect(os.RemoveAll(filepath.Dir(builtChartDir))).To(Succeed())
	}
})

var _ = Describe("AWS HyperPod init container", func() {
	var chartDir string

	BeforeEach(func() {
		chartDir = builtChartDir
	})

	// Regression coverage: workspace-base volume, its init container, and the
	// workspace volumeMount must never depend on remoteAccess/directSSH being
	// enabled - omitting them leaves entrypoint-workspace-jupyterlab unpopulated
	// and the workspace pod crash-loops.
	assertSingleInitContainer := func(strategy accessStrategy, expectedName string) {
		podMods := strategy.Spec.DeploymentModifications.PodModifications

		Expect(podMods.Volumes).To(HaveLen(1), "expected exactly one volume")
		Expect(podMods.Volumes[0]["name"]).To(Equal("workspace-base"))

		Expect(podMods.InitContainers).To(HaveLen(1),
			"expected exactly one init container, got %v", podMods.InitContainers)
		Expect(podMods.InitContainers[0]["name"]).To(Equal(expectedName))

		Expect(podMods.PrimaryContainerModifications.VolumeMounts).To(HaveLen(1))
		Expect(podMods.PrimaryContainerModifications.VolumeMounts[0]["name"]).To(Equal("workspace-base"))
	}

	It("renders exactly one init container when remoteAccess and directSSH are both disabled", func() {
		strategy, err := renderAccessStrategy(chartDir)
		Expect(err).NotTo(HaveOccurred())
		assertSingleInitContainer(strategy, "workspace-init-container")
	})

	It("renders exactly one init container when remoteAccess is enabled", func() {
		strategy, err := renderAccessStrategy(chartDir,
			"--set", "remoteAccess.enabled=true",
			"--set", "aws.region=us-east-1",
			"--set", "remoteAccess.ssmManagedNodeRole=arn:aws:iam::123456789:role/SageMakerRole",
			"--set", "remoteAccess.ssmSidecarImage.containerRegistry=123456789.dkr.ecr.us-east-1.amazonaws.com",
			"--set", "remoteAccess.ssmSidecarImage.repository=ssm-sidecar",
			"--set", "remoteAccess.ssmSidecarImage.tag=latest",
		)
		Expect(err).NotTo(HaveOccurred())
		assertSingleInitContainer(strategy, "workspace-init-container")
	})

	It("renders exactly one init container when directSSH is enabled, not two", func() {
		strategy, err := renderAccessStrategy(chartDir,
			"--set", "directSSH.enabled=true",
			"--set", "directSSH.domain=workspaces.example.com",
			"--set", "directSSH.port=22",
			"--set", "directSSH.initImage.containerRegistry=123456789.dkr.ecr.us-east-1.amazonaws.com",
			"--set", "directSSH.initImage.repository=direct-ssh-init",
			"--set", "directSSH.initImage.tag=latest",
		)
		Expect(err).NotTo(HaveOccurred())
		assertSingleInitContainer(strategy, "direct-ssh-init")
	})
})
