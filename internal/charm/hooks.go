package charm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/canonical/pebble/client"
	"github.com/gruyaume/charm-libraries/certificates"
	"github.com/gruyaume/charm-libraries/prometheus"
	"github.com/gruyaume/goops"
	"github.com/gruyaume/goops/commands"
)

const (
	KeyPath                    = "/etc/notary/config/key.pem"
	CertPath                   = "/etc/notary/config/cert.pem"
	ConfigPath                 = "/etc/notary/config/notary.yaml"
	APIPort                    = 2111
	CharmAccountUsername       = "charm@notary.com"
	NotaryLoginSecretLabel     = "NOTARY_LOGIN"
	MetricsIntegrationName     = "metrics"
	TLSRequiresIntegrationName = "certificates"
)

func HandleDefaultHook(ctx context.Context, hookContext *goops.HookContext) {
	isLeader, err := hookContext.Commands.IsLeader()
	if err != nil {
		hookContext.Commands.JujuLog(commands.Warning, "is-leader fail:", err.Error())
		return
	}

	if isLeader {
		// Own the secret
		// Store private key in the secret
		// Set the secret URI to the peer relation
		// Save the certificate to the peer relation
		return
	} else {
		// Parse peer relation databag
		// Get secret URI and certificate
		// Get the private key from the secret
		return
	}
}

func ensureLeader(ctx context.Context, hookContext *goops.HookContext) error {
	isLeader, err := hookContext.Commands.IsLeader()
	if err != nil {
		hookContext.Commands.JujuLog(commands.Warning, "Could not check if unit is leader:", err.Error())
		return fmt.Errorf("could not check if unit is leader: %w", err)
	}

	if !isLeader {
		hookContext.Commands.JujuLog(commands.Warning, "Unit is not leader")
		return fmt.Errorf("unit is not leader")
	}

	hookContext.Commands.JujuLog(commands.Info, "Unit is leader")

	return nil
}

func writePrometheus(ctx context.Context, hookContext *goops.HookContext, charmName string) {
	prometheusIntegration := &prometheus.Integration{
		HookContext:  hookContext,
		RelationName: MetricsIntegrationName,
		CharmName:    charmName,
		Jobs: []*prometheus.Job{
			{
				Scheme:      "https",
				TLSConfig:   prometheus.TLSConfig{InsecureSkipVerify: true},
				MetricsPath: "/metrics",
				StaticConfigs: []prometheus.StaticConfig{
					{
						Targets: []string{getHostname(hookContext)},
					},
				},
			},
		},
	}

	err := prometheusIntegration.Write()
	if err != nil {
		hookContext.Commands.JujuLog(commands.Debug, "Could not write prometheus integration:", err.Error())
		return
	}

	hookContext.Commands.JujuLog(commands.Info, "Prometheus integration written")
}

func syncConfig(ctx context.Context, hookContext *goops.HookContext, pebble *client.Client) error {
	expectedConfig, err := getExpectedConfig()
	if err != nil {
		hookContext.Commands.JujuLog(commands.Error, "Could not get expected config:", err.Error())
		return fmt.Errorf("could not get expected config: %w", err)
	}

	err = pushFile(pebble, string(expectedConfig), "/etc/notary/config/notary.yaml")
	if err != nil {
		hookContext.Commands.JujuLog(commands.Error, "Could not push config file:", err.Error())
		return fmt.Errorf("could not push config file: %w", err)
	}

	hookContext.Commands.JujuLog(commands.Info, "Config file pushed")

	return nil
}

func syncPebbleService(ctx context.Context, hookContext *goops.HookContext, pebble *client.Client, restart bool) error {
	err := addPebbleLayer(pebble)
	if err != nil {
		hookContext.Commands.JujuLog(commands.Error, "Could not add pebble layer:", err.Error())
		return fmt.Errorf("could not add pebble layer: %w", err)
	}

	if restart {
		err := restartPebbleService(pebble)
		if err != nil {
			hookContext.Commands.JujuLog(commands.Error, "Could not restart pebble service:", err.Error())
			return fmt.Errorf("could not restart pebble service: %w", err)
		}

		hookContext.Commands.JujuLog(commands.Info, "Pebble service restarted")
	}

	hookContext.Commands.JujuLog(commands.Info, "Pebble layer added")

	err = startPebbleService(pebble)
	if err != nil {
		hookContext.Commands.JujuLog(commands.Error, "Could not start pebble service:", err.Error())
		return fmt.Errorf("could not start pebble service: %w", err)
	}

	hookContext.Commands.JujuLog(commands.Info, "Pebble service started")

	return nil
}

func sendCertificate(
	provider certificates.IntegrationProvider,
	relationID string,
	req *notary.CertificateRequest,
) error {
	chain := notary.Serialize(req.CertificateChain)
	opts := &certificates.SetRelationCertificateOptions{
		RelationID:                relationID,
		CA:                        chain[1],
		Chain:                     chain,
		CertificateSigningRequest: req.CSR,
		Certificate:               chain[0],
	}

	return provider.SetRelationCertificate(opts)
}

func NewNotaryClient(certPEM string) (*notary.Client, error) {
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM([]byte(certPEM)); !ok {
		return nil, fmt.Errorf("invalid root cert PEM")
	}

	cfg := &notary.Config{
		BaseURL:   fmt.Sprintf("https://127.0.0.1:%d", APIPort),
		TLSConfig: &tls.Config{RootCAs: roots},
	}

	return notary.New(cfg)
}

func loginNotaryClient(hookContext *goops.HookContext, client *notary.Client) error {
	secret, err := hookContext.Commands.SecretGet(&commands.SecretGetOptions{
		Refresh: true,
		Label:   NotaryLoginSecretLabel,
	})
	if err != nil {
		return fmt.Errorf("could not get secret: %w", err)
	}

	if secret == nil {
		return fmt.Errorf("secret is empty")
	}

	password := secret["password"]
	if password == "" {
		return fmt.Errorf("password is empty")
	}

	err = client.Login(&notary.LoginOptions{
		Username: CharmAccountUsername,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("could not login to notary: %w", err)
	}

	return nil
}

func integrationCreated(hookContext *goops.HookContext, name string) bool {
	relationIDs, err := hookContext.Commands.RelationIDs(&commands.RelationIDsOptions{
		Name: name,
	})
	if err != nil {
		return false
	}

	if len(relationIDs) == 0 {
		return false
	}

	return true
}

func syncSelfSignedCertificate(hookContext *goops.HookContext, pebble *client.Client) (bool, error) {
	// FIXME: somewhere to store the cert private key
	// - either stash it in a file
	// - or store it in a secret
	certContent, _ := getFileContent(pebble, CertPath)

	if certContent != "" {
		hookContext.Commands.JujuLog(commands.Info, "Certificate already exists, skipping generation")
		return false, nil
	}

	cert, key, err := certificates.GenerateCertificate(&certificates.GenerateCertificateOpts{
		CommonName:       "127.0.0.1",
		ValidityDuration: 365 * 24 * time.Hour,
		SANIPAddresses:   []net.IP{net.ParseIP("127.0.0.1")},
	})
	if err != nil {
		return false, fmt.Errorf("could not generate certificate: %w", err)
	}

	hookContext.Commands.JujuLog(commands.Info, "Certificate generated")

	err = pushFile(pebble, cert, "/etc/notary/config/cert.pem")
	if err != nil {
		return false, fmt.Errorf("could not push certificate: %w", err)
	}

	hookContext.Commands.JujuLog(commands.Info, "Certificate pushed")

	err = pushFile(pebble, key, "/etc/notary/config/key.pem")
	if err != nil {
		return false, fmt.Errorf("could not push key: %w", err)
	}

	hookContext.Commands.JujuLog(commands.Info, "Key pushed")

	return true, nil
}

// syncTlsProviderCertificate makes a certificate request to the TLS provider
// and pushes the certificate and key to the pebble client.
func syncTlsProviderCertificate(hookContext *goops.HookContext, pebble *client.Client) (bool, error) {
	changed := false
	tlsRequirerIntegration := certificates.IntegrationRequirer{
		HookContext:  hookContext,
		RelationName: TLSRequiresIntegrationName,
		CertificateRequest: certificates.CertificateRequestAttributes{
			CommonName:          getHostname(hookContext),
			SansDNS:             []string{getHostname(hookContext)},
			SansIP:              []string{"127.0.0.1"},
			CountryName:         "CA",
			StateOrProvinceName: "QC",
			LocalityName:        "Montreal",
		},
	}

	err := tlsRequirerIntegration.Request()
	if err != nil {
		return changed, fmt.Errorf("could not request certificate: %w", err)
	}

	hookContext.Commands.JujuLog(commands.Info, "Certificate requested")

	providerCert, err := tlsRequirerIntegration.GetProviderCertificate()
	if err != nil {
		return changed, fmt.Errorf("could not get certificate: %w", err)
	}

	if len(providerCert) == 0 {
		return changed, fmt.Errorf("no certificate found")
	}

	if providerCert[0].Certificate == "" {
		return changed, fmt.Errorf("certificate is empty")
	}

	hookContext.Commands.JujuLog(commands.Info, "Certificate received")

	privateKey, err := tlsRequirerIntegration.GetPrivateKey()
	if err != nil {
		return changed, fmt.Errorf("could not get private key: %w", err)
	}

	existingPrivateKey, _ := getFileContent(pebble, KeyPath)

	if existingPrivateKey != privateKey {
		hookContext.Commands.JujuLog(commands.Warning, "Private key is different")

		err = pushFile(pebble, privateKey, KeyPath)
		if err != nil {
			return changed, fmt.Errorf("could not push key: %w", err)
		}

		hookContext.Commands.JujuLog(commands.Info, "Key pushed")

		changed = true
	}

	existingCertificate, _ := getFileContent(pebble, CertPath)
	if existingCertificate != providerCert[0].Certificate {
		hookContext.Commands.JujuLog(commands.Warning, "Certificate is different")

		err = pushFile(pebble, providerCert[0].Certificate, CertPath)
		if err != nil {
			return changed, fmt.Errorf("could not push certificate: %w", err)
		}

		hookContext.Commands.JujuLog(commands.Info, "Certificate pushed")

		changed = true
	}

	return changed, nil
}

func syncAccessCertificate(ctx context.Context, hookContext *goops.HookContext) (bool, error) {
	var changed bool

	if !integrationCreated(hookContext, TLSRequiresIntegrationName) {
		hookContext.Commands.JujuLog(commands.Info, "`certificates` integration not created")
	} else {
		hookContext.Commands.JujuLog(commands.Info, "`certificates` integration created")
	}
	return changed, nil
}

func SetStatus(ctx context.Context, hookContext *goops.HookContext) {
	status := commands.StatusActive

	message := ""

	statusSetOpts := &commands.StatusSetOptions{
		Name:    status,
		Message: message,
	}

	err := hookContext.Commands.StatusSet(statusSetOpts)
	if err != nil {
		hookContext.Commands.JujuLog(commands.Error, "Could not set status:", err.Error())
		return
	}

	hookContext.Commands.JujuLog(commands.Info, "Status set to active")
}

func getHostname(hookContext *goops.HookContext) string {
	modelName := hookContext.Environment.JujuModelName()
	unitName := hookContext.Environment.JujuUnitName()
	appName := strings.Split(unitName, "/")[0]
	unitNumber := strings.Split(unitName, "/")[1]
	unitHostname := fmt.Sprintf("%s-%s.%s-endpoints.%s.svc.cluster.local:%d", appName, unitNumber, appName, modelName, APIPort)

	return unitHostname
}
