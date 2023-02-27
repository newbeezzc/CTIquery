# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json


def output_json(file_name):
    # Variables
    # api_url = "http://113.54.217.126:4000"
    # api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    api_url = "http://localhost:4000"
    api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    properties = """
        id
        standard_id
        entity_type
        parent_types
        spec_version
        created_at
        updated_at
        createdBy {
            ... on Identity {
                id
                standard_id
                entity_type
                parent_types
                spec_version
                identity_class
                name
                description
                roles
                contact_information
                x_opencti_aliases
                created
                modified
                objectLabel {
                    edges {
                        node {
                            id
                            value
                            color
                        }
                    }
                }
            }
            ... on Organization {
                x_opencti_organization_type
                x_opencti_reliability
            }
            ... on Individual {
                x_opencti_firstname
                x_opencti_lastname
            }
        }
        objectMarking {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    definition_type
                    definition
                    created
                    modified
                    x_opencti_order
                    x_opencti_color
                }
            }
        }
        objectLabel {
            edges {
                node {
                    id
                    value
                    color
                }
            }
        }
        externalReferences {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    source_name
                    description
                    url
                    hash
                    external_id
                    created
                    modified
                    importFiles {
                        edges {
                            node {
                                id
                                name
                                size
                                metaData {
                                    mimetype
                                    version
                                }
                            }
                        }
                    }
                }
            }
        }
        stixCoreRelationships {
            edges {
                node {
                    id
                    standard_id
                    entity_type
                    from {
                        ... on StixCyberObservable {
                            id
                            standard_id
                            entity_type
                            parent_types
                            observable_value
                        }
                    }
                    to {
                        ... on AutonomousSystem {
                            id
                            standard_id
                            entity_type
                            observable_value
                            number
                        }
                        ... on Location {
                            id
                            standard_id
                            entity_type
                            name
                            latitude
                            longitude
                        }                                            
                    }
                    relationship_type
                }
            }
        }
        observable_value
        x_opencti_description
        x_opencti_score
        indicators {
            edges {
                node {
                    id
                    pattern
                    pattern_type
                }
            }
        }
        ... on AutonomousSystem {
            number
            name
            rir
        }
        ... on Directory {
            path
            path_enc
            ctime
            mtime
            atime
        }
        ... on DomainName {
            value
        }
        ... on EmailAddr {
            value
            display_name
        }
        ... on EmailMessage {
            is_multipart
            attribute_date
            content_type
            message_id
            subject
            received_lines
            body
        }
        ... on Artifact {
            mime_type
            payload_bin
            url
            encryption_algorithm
            decryption_key
            hashes {
                algorithm
                hash
            }
            importFiles {
                edges {
                    node {
                        id
                        name
                        size
                    }
                }
            }
        }
        ... on StixFile {
            extensions
            size
            name
            name_enc
            magic_number_hex
            mime_type
            ctime
            mtime
            atime
            x_opencti_additional_names
            hashes {
                algorithm
                hash
            }
        }
        ... on X509Certificate {
            is_self_signed
            version
            serial_number
            signature_algorithm
            issuer
            subject
            subject_public_key_algorithm
            subject_public_key_modulus
            subject_public_key_exponent
            validity_not_before
            validity_not_after
            hashes {
                algorithm
                hash
            }
        }
        ... on IPv4Addr {
            value
        }
        ... on IPv6Addr {
            value
        }
        ... on MacAddr {
            value
        }
        ... on Mutex {
            name
        }
        ... on NetworkTraffic {
            extensions
            start
            end
            is_active
            src_port
            dst_port
            protocols
            src_byte_count
            dst_byte_count
            src_packets
            dst_packets
        }
        ... on Process {
            extensions
            is_hidden
            pid
            created_time
            cwd
            command_line
            environment_variables
        }
        ... on Software {
            name
            cpe
            swid
            languages
            vendor
            version
        }
        ... on Url {
            value
        }
        ... on UserAccount {
            extensions
            user_id
            credential
            account_login
            account_type
            display_name
            is_service_account
            is_privileged
            can_escalate_privs
            is_disabled
            account_created
            account_expires
            credential_last_changed
            account_first_login
            account_last_login
        }
        ... on WindowsRegistryKey {
            attribute_key
            modified_time
            number_of_subkeys
        }
        ... on WindowsRegistryValueType {
            name
            data
            data_type
        }
        ... on CryptographicKey {
            value
        }
        ... on CryptocurrencyWallet {
            value
        }
        ... on Hostname {
            value
        }
        ... on Text {
            value
        }
        ... on UserAgent {
            value
        }
        importFiles {
            edges {
                node {
                    id
                    name
                    size
                    metaData {
                        mimetype
                        version
                    }
                }
            }
        }
    """
    filter = [{"key": "value", "values": "195.20.50.201", "filterMode": "and"}]
    results = opencti_api_client.stix_cyber_observable.list(types=["IPv4-Addr", "IPv6-Addr"], first=500,
                                                            getAll=False, customAttributes=properties, filters=filter)  # 默认100条，指定数目使用first参数

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as IP_detail:
        IP_items = []
        for result in results:
            IP_item = defaultdict(list)
            IP_item["IP"] = result["observable_value"]  # IP
            IP_item["IP_type"] = result["entity_type"]  # IP类型
            country = None
            city = None
            AS_name = None
            ASN = None
            latitude = None
            longitude = None
            if result["stixCoreRelationships"] != []:
                for relation in result["stixCoreRelationships"]:
                    relation_type = relation["relationship_type"]
                    if relation["to"] == {}:
                        continue
                    to_entity_type = relation["to"]["entity_type"]
                    if relation_type == "located-at":
                        if to_entity_type == "Country":
                            country = relation["to"]["name"]
                            latitude, longitude = (relation["to"]["latitude"], relation["to"]["longitude"]) if city is None else (latitude, longitude)
                        elif to_entity_type == "City":
                            city = relation["to"]["name"]
                            latitude, longitude = relation["to"]["latitude"], relation["to"]["longitude"]
                    AS_name, ASN = (relation["to"]["observable_value"], relation["to"]["number"]) if relation_type == "belongs-to" and to_entity_type == "Autonomous-System" else (AS_name, ASN)
                    
            IP_item["country"] = country  # 国家
            IP_item["province/state"] = None  # 省份/州
            IP_item["city"] = city  # 城市
            IP_item["AS_organization_name"] = AS_name  # AS组织名称
            IP_item["ASN"] = ASN  # ASN
            IP_item["latitude"] = latitude  # 纬度
            IP_item["longitude"] = longitude  # 经度

            IP_items.append(IP_item)

        IP_json_str = json.dumps(
            IP_items, indent=4, ensure_ascii=False
        )
        IP_detail.write(IP_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="IPAddr_1.json"
    )
