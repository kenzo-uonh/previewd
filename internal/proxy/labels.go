package proxy

import "fmt"

// GenerateLabels constructs Traefik dynamic routing configurations.
func GenerateLabels(envID string, port int, baseDomain string) map[string]string {
	return map[string]string{
		"traefik.enable": "true",
		fmt.Sprintf("traefik.http.routers.%s.rule", envID):                      fmt.Sprintf("Host(`%s.%s`)", envID, baseDomain),
		fmt.Sprintf("traefik.http.services.%s.loadbalancer.server.port", envID): fmt.Sprintf("%d", port),
		"traefik.docker.network":                                                "previewd-proxy",
	}
}
