# Copyright 2025 Krzysztof Taraszka and The Miget Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import requests
from typing import Dict, Optional, Union
import json


class CaddyAPIClient:
    def __init__(self, base_url: str = "http://localhost:2019"):
        """Initialize the Caddy API client.

        Args:
            base_url (str): Base URL for the Caddy API (e.g., http://localhost:2019)
        """
        self.base_url = base_url.rstrip('/')  # Remove trailing slash if present

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, headers: Optional[Dict] = None) -> requests.Response:
        """Make a request to the Caddy API.

        Args:
            method (str): HTTP method (GET, POST, etc.)
            endpoint (str): API endpoint
            data (Optional[Dict], optional): Data to send. Defaults to None.
            headers (Optional[Dict], optional): Custom headers. Defaults to None.

        Returns:
            requests.Response: Response from the API
        """
        url = f"{self.base_url}{endpoint}"
        default_headers = {'Content-Type': 'application/json'}
        if headers is not None:
            default_headers.update(headers)
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=default_headers,
                json=data if data else None,
                timeout=10  # Add timeout to prevent hanging
            )
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed: {str(e)}")

    def _get_tls_config(self) -> Dict:
        """Get current TLS configuration.

        Returns:
            Dict: Current TLS configuration
        """
        try:
            response = self._make_request('GET', '/config/apps/tls')
            return response.json()
        except Exception:
            return {}

    def _update_tls_config(self, new_config: Dict) -> None:
        """Update TLS configuration.

        Args:
            new_config (Dict): New TLS configuration
        """
        try:
            # First try to get existing config
            response = self._make_request('GET', '/config/apps/tls')
            current_config = response.json()
        except Exception:
            # If no config exists, start with empty one
            current_config = {}

        # If automation policies exist, merge them
        if 'automation' in new_config:
            if 'automation' not in current_config:
                current_config['automation'] = {'policies': []}
            
            # Add new policies
            current_policies = current_config['automation']['policies']
            new_policies = new_config['automation']['policies']
            
            # Remove any existing policies for the same domains
            for new_policy in new_policies:
                current_policies = [
                    p for p in current_policies 
                    if not any(subject in new_policy['subjects'] for subject in p.get('subjects', []))
                ]
            
            # Add new policies
            current_policies.extend(new_policies)
            current_config['automation']['policies'] = current_policies

        # Delete existing config first
        try:
            self._make_request('DELETE', '/config/apps/tls')
        except Exception:
            pass

        # Then add the updated config
        self._make_request('POST', '/config/apps/tls', data=current_config)

    def add_domain_with_auto_tls(self, domain: str, target: str, target_port: int,
                            enable_security_headers: bool = False, enable_hsts: bool = False,
                            frame_options: str = "DENY", enable_compression: bool = False,
                            redirect_mode: str = None) -> bool:
        """Add or update domain with auto TLS configuration.

        Args:
            domain (str): Domain name
            target (str): Target host (IP or FQDN) for reverse proxy
            target_port (int): Target port for reverse proxy
            enable_security_headers (bool, optional): Enable security headers. Defaults to False.
            enable_hsts (bool, optional): Enable HSTS. Defaults to False.
            frame_options (str, optional): X-Frame-Options value. Defaults to "DENY".
            enable_compression (bool, optional): Enable compression. Defaults to False.
            redirect_mode (str, optional): Redirect mode. Can be "www_to_domain" or "domain_to_www". Defaults to None.

        Returns:
            bool: True if successful
        """
        try:
            # Get current config
            response = self._make_request('GET', '/config/')
            config = response.json()

            # Initialize HTTP server config if not present
            if 'apps' not in config:
                config['apps'] = {}
            if 'http' not in config['apps']:
                config['apps']['http'] = {}
            if 'servers' not in config['apps']['http']:
                config['apps']['http']['servers'] = {}
            if 'srv0' not in config['apps']['http']['servers']:
                config['apps']['http']['servers']['srv0'] = {}
            if 'routes' not in config['apps']['http']['servers']['srv0']:
                config['apps']['http']['servers']['srv0']['routes'] = []

            # Create route handlers
            handlers = []

            # Add security headers if enabled
            if enable_security_headers:
                security_headers = self._get_security_headers(enable_hsts, frame_options)
                handlers.append({
                    "handler": "headers",
                    "response": {
                        "set": security_headers
                    }
                })

            # Add compression if enabled
            if enable_compression:
                handlers.append({
                    "handler": "encode",
                    "encodings": {
                        "gzip": {},
                        "zstd": {}
                    }
                })

            # Add reverse proxy handler
            handlers.append(self._get_reverse_proxy_handler(target, target_port))

            # Create routes configuration
            routes = []
            
            # Handle domain names for redirect
            base_domain = domain.replace('www.', '') if domain.startswith('www.') else domain
            www_domain = f"www.{base_domain}"
            
            # Add redirect route if redirect_mode is specified
            if redirect_mode:
                source_domain = www_domain if redirect_mode == "www_to_domain" else base_domain
                target_domain = base_domain if redirect_mode == "www_to_domain" else www_domain
                
                redirect_route = {
                    "@id": f"{source_domain}-redirect",
                    "match": [{"host": [source_domain]}],
                    "handle": [{
                        "handler": "static_response",
                        "headers": {
                            "Location": [f"https://{target_domain}{{http.request.uri}}"]
                        },
                        "status_code": 308
                    }]
                }
                routes.append(redirect_route)

            # Add main route
            main_route = {
                "@id": domain,
                "match": [{"host": [domain]}],
                "terminal": True,
                "handle": handlers
            }
            routes.append(main_route)

            # Get current routes
            current_routes = config['apps']['http']['servers']['srv0']['routes']

            # Remove any existing routes for this domain
            current_routes = [r for r in current_routes if not (
                r.get('@id') == domain or  # Main domain route
                r.get('@id') == f"{domain}-redirect" or  # Redirect route for this domain
                (r.get('match', [{}])[0].get('host', []) == [domain])  # Any route matching this domain
            )]

            # Find position after security routes but before domain routes
            insert_pos = 0
            for i, r in enumerate(current_routes):
                if r.get('handle', [{}])[0].get('handler') == 'static_response':
                    insert_pos = i + 1
                elif '@id' in r:
                    break

            # Insert domain routes
            current_routes[insert_pos:insert_pos] = routes

            # Update routes in config
            config['apps']['http']['servers']['srv0']['routes'] = current_routes

            # Configure auto TLS
            if 'tls' not in config['apps']:
                config['apps']['tls'] = {}
            if 'automation' not in config['apps']['tls']:
                config['apps']['tls']['automation'] = {
                    'policies': []
                }

            # Find or create on_demand policy
            on_demand_policy = None
            for policy in config['apps']['tls']['automation'].get('policies', []):
                if policy.get('on_demand'):
                    on_demand_policy = policy
                    break

            if on_demand_policy is None:
                on_demand_policy = {
                    'issuers': [
                        {
                            'module': 'acme',
                            'email': 'auto-tls@miget.com'
                        },
                        {
                            'module': 'acme',
                            'email': 'auto-tls@miget.com',
                            'ca': 'https://acme.zerossl.com/v2/DV90'
                        }
                    ],
                    'on_demand': True,
                    'key_type': 'p384',
                    'subjects': []
                }
                config['apps']['tls']['automation']['policies'].append(on_demand_policy)

            # Add domain to subjects if not already present
            if 'subjects' not in on_demand_policy:
                on_demand_policy['subjects'] = []
            if domain not in on_demand_policy['subjects']:
                on_demand_policy['subjects'].append(domain)

            # Update configuration
            self._make_request('POST', '/config/', data=config)
            return True

        except Exception as e:
            raise Exception(f"Failed to add domain with auto TLS: {str(e)}")

    def add_domain_with_tls(self, domain: str, target: str, target_port: int, certificate: str, private_key: str,
                           cert_selection_policy: Optional[Dict] = None, redirect_mode: str = None) -> bool:
        """Add domain with TLS certificate.

        Args:
            domain (str): Domain name
            target (str): Target host (IP or FQDN) for reverse proxy
            target_port (int): Target port for reverse proxy
            certificate (str): PEM-encoded certificate
            private_key (str): PEM-encoded private key
            cert_selection_policy (Optional[Dict], optional): Certificate selection policy. Defaults to None.
                If not provided, will automatically create one based on the certificate's serial number.
            redirect_mode (str, optional): Redirect mode. Can be "www_to_domain" or "domain_to_www". Defaults to None.

        Returns:
            bool: True if successful
        """
        try:
            # Extract certificate serial number for tagging
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            import base64
            from datetime import datetime

            # Parse certificate to get serial number from the first certificate in the bundle
            cert_blocks = []
            current_block = []
            in_cert = False
            
            # Split into individual certificate blocks
            for line in certificate.splitlines():
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    current_block = [line]
                elif "-----END CERTIFICATE-----" in line:
                    in_cert = False
                    current_block.append(line)
                    cert_blocks.append("\n".join(current_block))
                elif in_cert:
                    current_block.append(line)
            
            if not cert_blocks:
                raise Exception("No valid certificates found in the provided certificate data")
            
            # Use the first certificate (server cert) for the serial number
            first_cert = cert_blocks[0]
            cert_lines = []
            in_cert = False
            for line in first_cert.splitlines():
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    continue
                elif "-----END CERTIFICATE-----" in line:
                    in_cert = False
                    continue
                if in_cert:
                    cert_lines.append(line)
            
            cert_der = base64.b64decode("".join(cert_lines))
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            serial_number = format(cert.serial_number, 'x')  # Convert to hex string
            
            # Create tag in format domain-serial-timestamp
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            cert_tag = f"{domain}-{serial_number}-{timestamp}"

            # Create routes configuration
            routes = []
            
            # Handle domain names for redirect
            base_domain = domain.replace('www.', '') if domain.startswith('www.') else domain
            www_domain = f"www.{base_domain}"
            
            # Add redirect route if redirect_mode is specified
            if redirect_mode:
                source_domain = www_domain if redirect_mode == "www_to_domain" else base_domain
                target_domain = base_domain if redirect_mode == "www_to_domain" else www_domain
                
                redirect_route = {
                    "@id": f"{source_domain}-redirect",
                    "match": [{"host": [source_domain]}],
                    "handle": [{
                        "handler": "static_response",
                        "headers": {
                            "Location": [f"https://{target_domain}{{http.request.uri}}"]
                        },
                        "status_code": 308
                    }]
                }
                routes.append(redirect_route)

            # Add main route
            main_route = {
                "@id": domain,
                "match": [{"host": [domain]}],
                "handle": [{
                    "handler": "subroute",
                    "routes": [{
                        "handle": [self._get_reverse_proxy_handler(target, target_port)]
                    }]
                }]
            }
            routes.append(main_route)

            # Get current config
            response = self._make_request('GET', '/config/')
            config = response.json()

            # Add routes to config
            if 'apps' not in config:
                config['apps'] = {}
            if 'http' not in config['apps']:
                config['apps']['http'] = {}
            if 'servers' not in config['apps']['http']:
                config['apps']['http']['servers'] = {}
            if 'srv0' not in config['apps']['http']['servers']:
                config['apps']['http']['servers']['srv0'] = {}
            if 'routes' not in config['apps']['http']['servers']['srv0']:
                config['apps']['http']['servers']['srv0']['routes'] = []

            config['apps']['http']['servers']['srv0']['routes'].extend(routes)

            # Add certificate configuration
            if 'tls' not in config['apps']:
                config['apps']['tls'] = {}
            if 'certificates' not in config['apps']['tls']:
                config['apps']['tls']['certificates'] = {}
            
            cert_config = {
                "certificate": certificate,
                "key": private_key,
                "tags": [cert_tag]  # Use domain-serial-timestamp tag
            }
            
            if 'load_pem' not in config['apps']['tls']['certificates']:
                config['apps']['tls']['certificates']['load_pem'] = [cert_config]
            else:
                # Remove any existing certificates with matching domain tag pattern
                config['apps']['tls']['certificates']['load_pem'] = [
                    cert for cert in config['apps']['tls']['certificates']['load_pem']
                    if not (any(tag.startswith(f"{domain}-") for tag in cert.get('tags', [])) or
                          any(tag.startswith('domain-') for tag in cert.get('tags', [])) or
                          domain in cert.get('tags', []))
                ]
                # Add the new certificate
                config['apps']['tls']['certificates']['load_pem'].append(cert_config)

            # Update TLS connection policies
            self._update_tls_connection_policies(config, domain, cert_tag=cert_tag)

            # Update the configuration
            self._make_request('POST', '/config/', data=config)
            return True

        except Exception as e:
            raise Exception(f"Failed to add domain: {str(e)}")

    def delete_domain(self, domain: str) -> bool:
        """Delete domain configuration.

        Args:
            domain (str): Domain name

        Returns:
            bool: True if successful
        """
        try:
            # Get current config
            response = self._make_request('GET', '/config/')
            config = response.json()

            # Get current routes
            routes = config['apps']['http']['servers']['srv0']['routes']

            # Remove domain routes, redirect routes, and ACME challenge routes
            routes = [r for r in routes if not (
                r.get('@id') == domain or  # Main domain route
                r.get('@id') == f"{domain}-redirect" or  # Redirect route for this domain
                (r.get('match', [{}])[0].get('host', []) == [domain])  # Any route matching this domain
            )]

            # Update routes
            config['apps']['http']['servers']['srv0']['routes'] = routes

            # Remove domain from TLS automation subjects if present
            if 'tls' in config['apps'] and 'automation' in config['apps']['tls']:
                for policy in config['apps']['tls']['automation'].get('policies', []):
                    if 'subjects' in policy and domain in policy['subjects']:
                        policy['subjects'].remove(domain)

            # Find certificate tags from TLS connection policies before removing them
            cert_tags_to_remove = set()
            if 'tls_connection_policies' in config['apps']['http']['servers']['srv0']:
                policies = config['apps']['http']['servers']['srv0']['tls_connection_policies']
                for policy in policies:
                    if ('match' in policy and 'sni' in policy['match'] and 
                        domain in policy['match']['sni'] and
                        'certificate_selection' in policy and
                        'all_tags' in policy['certificate_selection']):
                        cert_tags_to_remove.update(policy['certificate_selection']['all_tags'])

                # Remove TLS connection policies for this domain
                policies = [p for p in policies if not (
                    'match' in p and 'sni' in p['match'] and domain in p['match']['sni']
                )]
                if policies:
                    config['apps']['http']['servers']['srv0']['tls_connection_policies'] = policies
                else:
                    del config['apps']['http']['servers']['srv0']['tls_connection_policies']

            # Remove certificates with matching tags from the policy
            if cert_tags_to_remove and 'tls' in config['apps'] and 'certificates' in config['apps']['tls']:
                if 'load_pem' in config['apps']['tls']['certificates']:
                    # Filter out certificates with matching tags
                    config['apps']['tls']['certificates']['load_pem'] = [
                        cert for cert in config['apps']['tls']['certificates']['load_pem']
                        if not (set(cert.get('tags', [])) & cert_tags_to_remove)
                    ]
                    # Remove the certificates section if empty
                    if not config['apps']['tls']['certificates']['load_pem']:
                        del config['apps']['tls']['certificates']['load_pem']
                        if not config['apps']['tls']['certificates']:
                            del config['apps']['tls']['certificates']

            # Update configuration
            self._make_request('POST', '/config/', data=config)
            return True

        except Exception as e:
            raise Exception(f"Failed to delete domain: {str(e)}")

    def get_domain_config(self, domain: str) -> Dict:
        """Get domain configuration.

        Args:
            domain (str): Domain name

        Returns:
            Dict: Domain configuration
        """
        try:
            # Get current config
            response = self._make_request('GET', '/config/')
            config = response.json()

            # Find domain route
            route = None
            if 'apps' in config and 'http' in config['apps']:
                servers = config['apps']['http'].get('servers', {})
                for server_name, server in servers.items():
                    routes = server.get('routes', [])
                    for r in routes:
                        if r.get('@id') == domain:
                            route = r
                            break
                    if route:
                        break

            if not route:
                print(f"Warning: Route for domain {domain} not found")
                route = {}

            # Get certificate configuration
            cert_config = {}
            if 'apps' in config and 'tls' in config['apps']:
                tls_config = config['apps']['tls']
                
                # Check for auto TLS
                if 'automation' in tls_config:
                    for policy in tls_config['automation'].get('policies', []):
                        if policy.get('on_demand') and domain in policy.get('subjects', []):
                            cert_config = {
                                'type': 'auto_tls',
                                'policy': policy
                            }
                            break

                # Check for PEM certificates
                if not cert_config and 'certificates' in tls_config:
                    for cert in tls_config['certificates'].get('load_pem', []):
                        if domain in cert.get('tags', []):
                            cert_config = {
                                'type': 'pem',
                                'certificate': cert
                            }
                            break

            return {
                'route': route,
                'certificates': cert_config
            }

        except Exception as e:
            raise Exception(f"Failed to get domain config: {str(e)}")

    def _is_domain_using_auto_tls(self, config: Dict, domain: str) -> bool:
        """Check if a domain is using auto TLS.

        Args:
            config (Dict): Current Caddy config
            domain (str): Domain to check

        Returns:
            bool: True if domain is using auto TLS
        """
        if 'tls' in config['apps'] and 'automation' in config['apps']['tls']:
            for policy in config['apps']['tls']['automation'].get('policies', []):
                if policy.get('on_demand') and domain in policy.get('subjects', []):
                    return True
        return False

    def _get_auto_tls_policy(self, domain: str) -> Dict:
        """Get TLS connection policy for auto TLS domain.

        Args:
            domain (str): Domain name

        Returns:
            Dict: TLS connection policy for auto TLS
        """
        return {
            "match": {"sni": [domain]},
            "protocol_min": "tls1.2",
            "protocol_max": "tls1.3",  # Enforce TLS 1.3 as max
            "cipher_suites": [
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            ],
            "curves": ["x25519", "secp256r1", "secp384r1"],
            "alpn": ["h3", "h2", "h1"]  # Enable HTTP/3 (QUIC)
        }

    def _get_custom_cert_policy(self, domain: str, cert_tag: str) -> Dict:
        """Get TLS connection policy for custom certificate domain.

        Args:
            domain (str): Domain name
            cert_tag (str): Certificate tag

        Returns:
            Dict: TLS connection policy for custom certificate
        """
        return {
            "match": {"sni": [domain]},
            "protocol_min": "tls1.2",
            "protocol_max": "tls1.3",
            "cipher_suites": [
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            ],
            "curves": ["x25519", "secp256r1", "secp384r1"],
            "alpn": ["h3", "h2", "h1"],
            "certificate_selection": {"all_tags": [cert_tag]}
        }

    def _get_reverse_proxy_handler(self, target: str, target_port: int) -> Dict:
        """Get reverse proxy handler with X-Real-Ip header.

        This ensures the real client IP is forwarded to upstream services,
        not the IP of intermediate proxies.

        Args:
            target (str): Target host (IP or FQDN)
            target_port (int): Target port

        Returns:
            Dict: Reverse proxy handler configuration
        """
        return {
            "handler": "reverse_proxy",
            "headers": {
                "request": {
                    "set": {
                        "X-Real-Ip": ["{http.request.remote.host}"]
                    }
                }
            },
            "upstreams": [{
                "dial": f"{target}:{target_port}"
            }]
        }

    def _get_security_headers(self, enable_hsts: bool = True, frame_options: str = "DENY") -> dict:
        """Generate security headers configuration.

        Args:
            enable_hsts (bool): Enable HSTS header
            frame_options (str): X-Frame-Options value (DENY, SAMEORIGIN)

        Returns:
            dict: Security headers configuration
        """
        headers = {
            "X-Content-Type-Options": ["nosniff"],
            "X-Frame-Options": [frame_options],
            "Referrer-Policy": ["strict-origin-when-cross-origin"],
        }
        
        if enable_hsts:
            headers["Strict-Transport-Security"] = ["max-age=31536000; includeSubDomains"]
        
        return headers

    def _get_custom_headers(self, custom_headers: Dict[str, str]) -> dict:
        """Convert custom headers to Caddy format.

        Args:
            custom_headers (Dict[str, str]): Custom headers

        Returns:
            dict: Headers in Caddy format
        """
        return {k: [v] for k, v in custom_headers.items()}

    def _update_tls_connection_policies(self, config: Dict, domain: str, is_auto_tls: bool = False, cert_tag: str = None):
        """Update TLS connection policies for a domain.

        Args:
            config (Dict): Current Caddy config
            domain (str): Domain name
            is_auto_tls (bool): Whether domain uses auto TLS
            cert_tag (str): Certificate tag for custom certificate
        """
        # Initialize tls_connection_policies if not exists
        if 'tls_connection_policies' not in config['apps']['http']['servers']['srv0']:
            config['apps']['http']['servers']['srv0']['tls_connection_policies'] = []

        # Remove existing policy for this domain
        policies = config['apps']['http']['servers']['srv0']['tls_connection_policies']
        policies = [p for p in policies if domain not in p.get('match', {}).get('sni', [])]

        # Add policy based on type
        if is_auto_tls:
            policies.append(self._get_auto_tls_policy(domain))
        elif cert_tag:
            policies.append(self._get_custom_cert_policy(domain, cert_tag))

        # Always update the policies array, even if empty
        config['apps']['http']['servers']['srv0']['tls_connection_policies'] = policies

    def _should_remove_tls_connection_policies(self, config: Dict) -> bool:
        """Check if tls_connection_policies should be removed.
        
        Args:
            config (Dict): Current Caddy config
            
        Returns:
            bool: True if tls_connection_policies should be removed
        """
        # If there are no policies, it's safe to remove
        if not config['apps']['http']['servers']['srv0'].get('tls_connection_policies', []):
            return True

        # Get all domains from routes
        domains = []
        for route in config['apps']['http']['servers']['srv0'].get('routes', []):
            if '@id' in route:
                domains.append(route['@id'])

        # Check if all domains are using auto TLS
        return all(self._is_domain_using_auto_tls(config, domain) for domain in domains)

    def _normalize_domain(self, domain: str) -> str:
        """Remove www prefix from domain if present.

        Args:
            domain (str): Domain name

        Returns:
            str: Domain name without www prefix
        """
        return domain[4:] if domain.startswith('www.') else domain

    def update_domain(self, domain: str, target: str = None, target_port: int = None, 
                     certificate: str = None, private_key: str = None,
                     cert_selection_policy: Optional[Dict] = None,
                     redirect_mode: str = None) -> bool:
        """Update domain configuration.

        Args:
            domain (str): Domain name to update
            target (str, optional): New target host (IP or FQDN) for reverse proxy. Defaults to None.
            target_port (int, optional): New target port for reverse proxy. Defaults to None.
            certificate (str, optional): PEM-encoded certificate or "auto" for auto TLS. Defaults to None.
            private_key (str, optional): PEM-encoded private key. Required if certificate is PEM. Defaults to None.
            cert_selection_policy (Optional[Dict], optional): Certificate selection policy. Defaults to None.
                If not provided and certificate is updated, will automatically create one based on the certificate's serial number.
            redirect_mode (str, optional): Redirect mode. Can be "www_to_domain" or "domain_to_www". Defaults to None.

        Returns:
            bool: True if successful
        """
        try:
            # Get current config
            response = self._make_request('GET', '/config/')
            config = response.json()

            # Get current routes
            routes = config['apps']['http']['servers']['srv0']['routes']

            # Find existing route for this domain
            domain_route = None
            for route in routes:
                if route.get('@id') == domain:
                    domain_route = route
                    break

            if domain_route is None:
                raise Exception(f"Domain {domain} not found in configuration")

            # Update target if provided
            if target is not None and target_port is not None:
                # Create new handlers list with security headers and reverse proxy
                new_handlers = []
                
                # Add existing security headers if present
                for handler in domain_route['handle']:
                    if handler['handler'] == 'headers':
                        new_handlers.append(handler)
                    elif handler['handler'] == 'encode':
                        new_handlers.append(handler)

                # Add reverse proxy handler
                new_handlers.append(self._get_reverse_proxy_handler(target, target_port))

                # Update domain route with new handlers
                domain_route['handle'] = new_handlers

            # Update certificate if provided
            if certificate == "auto":
                # Remove domain from any existing TLS config
                if 'tls' in config['apps']:
                    # Remove from certificates if present
                    if 'certificates' in config['apps']['tls']:
                        if 'load_pem' in config['apps']['tls']['certificates']:
                            config['apps']['tls']['certificates']['load_pem'] = [
                                cert for cert in config['apps']['tls']['certificates']['load_pem']
                                if not (any(tag.startswith(f"{domain}-") for tag in cert.get('tags', [])))
                            ]
            elif certificate:
                # Handle PEM certificate update
                if not private_key:
                    raise Exception("Private key is required when updating PEM certificate")

                # Extract certificate serial number for tagging
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                import base64
                from datetime import datetime

                # Parse certificate to get serial number from the first certificate in the bundle
                cert_blocks = []
                current_block = []
                in_cert = False
                
                # Split into individual certificate blocks
                for line in certificate.splitlines():
                    if "-----BEGIN CERTIFICATE-----" in line:
                        in_cert = True
                        current_block = [line]
                    elif "-----END CERTIFICATE-----" in line:
                        in_cert = False
                        current_block.append(line)
                        cert_blocks.append("\n".join(current_block))
                    elif in_cert:
                        current_block.append(line)
                
                if not cert_blocks:
                    raise Exception("No valid certificates found in the provided certificate data")
                
                # Use the first certificate (server cert) for the serial number
                first_cert = cert_blocks[0]
                cert_lines = []
                in_cert = False
                for line in first_cert.splitlines():
                    if "-----BEGIN CERTIFICATE-----" in line:
                        in_cert = True
                        continue
                    elif "-----END CERTIFICATE-----" in line:
                        in_cert = False
                        continue
                    if in_cert:
                        cert_lines.append(line)
                
                cert_der = base64.b64decode("".join(cert_lines))
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                serial_number = format(cert.serial_number, 'x')  # Convert to hex string
                
                # Create tag in format domain-serial-timestamp
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                cert_tag = f"{domain}-{serial_number}-{timestamp}"

                # Create certificate configuration
                cert_config = {
                    "certificate": certificate,
                    "key": private_key,
                    "tags": [cert_tag]  # Use domain-serial-timestamp tag
                }

                # Add certificate selection policy if provided, otherwise create one based on cert tag
                if cert_selection_policy:
                    cert_config.update(cert_selection_policy)
                else:
                    cert_config["tags"] = [cert_tag]

                # Update certificates configuration
                if 'tls' not in config['apps']:
                    config['apps']['tls'] = {}
                if 'certificates' not in config['apps']['tls']:
                    config['apps']['tls']['certificates'] = {}
                if 'load_pem' not in config['apps']['tls']['certificates']:
                    config['apps']['tls']['certificates']['load_pem'] = []

                # Remove any existing certificates for this domain
                config['apps']['tls']['certificates']['load_pem'] = [
                    cert for cert in config['apps']['tls']['certificates']['load_pem']
                    if not (any(tag.startswith(f"{domain}-") for tag in cert.get('tags', [])))
                ]

                # Add new certificate
                config['apps']['tls']['certificates']['load_pem'].append(cert_config)

                # Update TLS connection policies
                self._update_tls_connection_policies(config, domain, cert_tag=cert_tag)

            # Update redirect route if redirect_mode is provided
            if redirect_mode:
                # Find existing redirect route
                redirect_route = None
                for route in routes:
                    if route.get('@id') == f"{domain}-redirect":
                        redirect_route = route
                        break

                # Create new redirect route if not found
                if not redirect_route:
                    # Normalize domain by removing www if present
                    base_domain = self._normalize_domain(domain)
                    source_domain = f"www.{base_domain}" if redirect_mode == "www_to_domain" else base_domain
                    target_domain = base_domain if redirect_mode == "www_to_domain" else f"www.{base_domain}"
                    
                    redirect_route = {
                        "@id": f"{domain}-redirect",
                        "match": [{"host": [source_domain]}],
                        "handle": [{
                            "handler": "static_response",
                            "headers": {
                                "Location": [f"https://{target_domain}{{http.request.uri}}"]
                            },
                            "status_code": 308
                        }]
                    }
                    routes.append(redirect_route)
                else:
                    # Update existing redirect route
                    base_domain = self._normalize_domain(domain)
                    source_domain = f"www.{base_domain}" if redirect_mode == "www_to_domain" else base_domain
                    target_domain = base_domain if redirect_mode == "www_to_domain" else f"www.{base_domain}"
                    
                    redirect_route['match'][0]['host'] = [source_domain]
                    redirect_route['handle'][0]['headers']['Location'] = [f"https://{target_domain}{{http.request.uri}}"]

            # Update configuration
            self._make_request('POST', '/config/', data=config)
            return True

        except Exception as e:
            raise Exception(f"Failed to update domain: {str(e)}")

    def reload(self) -> bool:
        """Force reload of Caddy configuration.
        Gets current config and sends it to /load with must-revalidate header.

        Returns:
            bool: True if successful
        """
        try:
            print("Getting current configuration...")
            response = self._make_request('GET', '/config/')
            config = response.json()

            print("Reloading configuration...")
            headers = {'Cache-Control': 'must-revalidate'}
            self._make_request('POST', '/load', data=config, headers=headers)
            print("Configuration reloaded successfully")
            return True

        except Exception as e:
            raise Exception(f"Failed to reload configuration: {str(e)}")
