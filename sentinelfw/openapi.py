"""SentinelFW OpenAPI 3.0 Specification Generator (Phase 30).

Provides complete, strictly-typed OpenAPI 3.0 documentation for all SentinelFW
management endpoints, policies, threat response, and observability APIs.
"""
from typing import Dict, Any
from .common import VERSION


def generate_openapi_spec() -> Dict[str, Any]:
    """Generates the canonical OpenAPI 3.0 schema dictionary for SentinelFW."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SentinelFW Enterprise NGFW Management API",
            "description": "Unified Management Plane REST API for SentinelFW Next-Generation Firewall, ZTNA, and Threat Response.",
            "version": VERSION,
            "contact": {
                "name": "SentinelFW Security Operations",
                "url": "https://github.com/sentinelfw/sentinelfw",
            },
            "license": {
                "name": "Apache-2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
            },
        },
        "servers": [
            {"url": "/api/v1", "description": "Local SentinelFW Management Node (v1)"}
        ],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "API Bearer token issued by /api/v1/tokens",
                },
                "CookieAuth": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "sfw_session",
                    "description": "Session cookie with mandatory sfw_csrf token for state-changing requests",
                },
                "FleetKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Fleet-Key",
                    "description": "Distributed node pre-shared fleet key",
                },
            },
            "schemas": {
                "StandardResponse": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "example": "ok"},
                        "message": {"type": "string"},
                    },
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "example": "forbidden"},
                        "message": {"type": "string"},
                    },
                    "required": ["error"],
                },
                "PolicyRule": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "example": 10},
                        "name": {"type": "string", "example": "Allow-HTTPS-Outbound"},
                        "action": {"type": "string", "enum": ["allow", "drop", "reject", "inspect"]},
                        "src_zone": {"type": "string", "example": "trust"},
                        "dst_zone": {"type": "string", "example": "untrust"},
                        "src_ip": {"type": "string", "example": "10.0.0.0/24"},
                        "dst_ip": {"type": "string", "example": "0.0.0.0/0"},
                        "app_id": {"type": "string", "example": "ssl"},
                        "service": {"type": "string", "example": "tcp/443"},
                        "ips_profile": {"type": "string", "example": "enterprise_strict"},
                        "tenant_id": {"type": "string", "example": "root"},
                    },
                    "required": ["action", "src_zone", "dst_zone"],
                },
                "BanRecord": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string", "example": "198.51.100.1"},
                        "reason": {"type": "string", "example": "Port scanning detected"},
                        "duration": {"type": "integer", "example": 86400},
                        "source": {"type": "string", "example": "engine"},
                        "permanent": {"type": "boolean", "example": False},
                    },
                    "required": ["ip"],
                },
                "VDOM": {
                    "type": "object",
                    "properties": {
                        "vdom_id": {"type": "string", "example": "corp-finance"},
                        "name": {"type": "string", "example": "Finance Department"},
                        "interfaces": {"type": "array", "items": {"type": "string"}},
                        "enabled": {"type": "boolean", "example": True},
                        "quotas": {
                            "type": "object",
                            "properties": {
                                "max_policies": {"type": "integer", "example": 500},
                                "max_sessions": {"type": "integer", "example": 50000},
                            },
                        },
                    },
                    "required": ["vdom_id", "name"],
                },
                "ZTNAEvaluationRequest": {
                    "type": "object",
                    "properties": {
                        "client_ip": {"type": "string", "example": "10.10.10.50"},
                        "app_name": {"type": "string", "example": "erp_internal"},
                        "posture": {
                            "type": "object",
                            "properties": {
                                "os": {"type": "string", "example": "linux"},
                                "edr_active": {"type": "boolean", "example": True},
                                "disk_encrypted": {"type": "boolean", "example": True},
                            },
                        },
                    },
                    "required": ["client_ip", "app_name"],
                },
            },
        },
        "security": [{"BearerAuth": []}, {"CookieAuth": []}],
        "paths": {
            "/policies": {
                "get": {
                    "summary": "List all configured firewall policies",
                    "responses": {
                        "200": {
                            "description": "List of active policies",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "policies": {
                                                "type": "array",
                                                "items": {"$ref": "#/components/schemas/PolicyRule"},
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
                "post": {
                    "summary": "Create a new firewall policy",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/PolicyRule"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Policy successfully created"},
                        "400": {"description": "Invalid policy or quota exceeded"},
                    },
                },
            },
            "/bans": {
                "get": {
                    "summary": "List currently banned IP addresses",
                    "responses": {
                        "200": {"description": "Dictionary of active bans"}
                    },
                },
                "post": {
                    "summary": "Ban an IP address",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/BanRecord"}
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "IP banned successfully"},
                        "400": {"description": "Protected/trusted rail refused or missing IP"},
                    },
                },
            },
            "/vdoms": {
                "get": {
                    "summary": "List virtual domains and multi-tenant quotas",
                    "responses": {
                        "200": {
                            "description": "List of virtual domains",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "vdoms": {
                                                "type": "array",
                                                "items": {"$ref": "#/components/schemas/VDOM"},
                                            }
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            },
            "/ztna/evaluate": {
                "post": {
                    "summary": "Evaluate ZTNA context and device posture for application access",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ZTNAEvaluationRequest"}
                            }
                        },
                    },
                    "responses": {
                        "200": {
                            "description": "Access verdict and rationale",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "allowed": {"type": "boolean"},
                                            "reason": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                },
            },
            "/forensics/incident_bundle": {
                "get": {
                    "summary": "Export a tamper-evident forensic incident bundle",
                    "parameters": [
                        {
                            "name": "target",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                            "description": "IP address or incident identifier",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Forensic evidence package"}
                    },
                },
            },
            "/overview": {
                "get": {
                    "summary": "High-level dashboard overview metrics",
                    "responses": {
                        "200": {"description": "Live metrics and system status"}
                    },
                }
            },
        },
    }
