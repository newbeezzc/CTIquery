# coding: utf-8
from pycti import OpenCTIApiClient
import hashlib
from datetime import datetime, date
from collections import defaultdict
import json
from utils import parse_date, parse_ioc_type, load_label_dict, cast_label


def output_json(file_name):
    # Variables
    api_url = "http://113.54.217.126:4000"
    api_token = "1AD9B432-2E47-2DEE-E4EC-017681B4DF2A"
    # api_url = "http://localhost:4000"
    # api_token = "2f5886e0-47e2-4e1a-955f-5b7df4813588"

    # OpenCTI initialization
    opencti_api_client = OpenCTIApiClient(api_url, api_token)

    # filter = [{"key": "value", "values": "ftp.scene.org", "filterMode": "and"}]
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
        observable_value
        x_opencti_description
        x_opencti_score
        indicators {
            edges {
                node {
                    id
                    pattern
                    pattern_type
                    revoked
                    indicator_types
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
    types = ["Domain-Name", "StixFile", "URL", "Email-Addr", "IPv4-Addr", "IPv6-Addr"]
    # types = ["StixFile"]
    results = opencti_api_client.stix_cyber_observable.list(first=100,
                                                            getAll=False, customAttributes=properties,
                                                            types=types)  # 默认100条，指定数目使用first参数
    label_dict = load_label_dict()  # 加载标签映射字典

    # 以下为对应字段
    with open(file_name, "w", newline="\n", encoding="utf-8") as intelligence_detail:
        intelligence_items = []
        for result in results:
            intelligence_item = defaultdict(list)
            intelligence_item["ioc"] = result["observable_value"]  # ioc
            intelligence_item["ioc_type"] = parse_ioc_type(result["entity_type"])  # ioc类型
            intelligence_item["malicious_evaluation"] = result["x_opencti_description"]  # 恶意评价
            intelligence_item["highest_intelligence_credibility"] = result["x_opencti_score"]  # 最高情报可信度
            sha1 = None
            sha256 = None
            hasMD5 = False
            try:
                for hash in result["hashes"]:
                    if hash["algorithm"] == 'MD5':
                        intelligence_item["ioc"] = hash["hash"]
                        hasMD5 = True
                    elif hash["algorithm"] == 'SHA-1':
                        sha1 = hash["hash"]
                    elif hash["algorithm"] == 'SHA-256':
                        sha256 = hash["hash"]
            except:
                pass
            if result["entity_type"] == "StixFile" and not hasMD5:  # 如果是文件但没有MD5则跳过
                continue
            intelligence_item["sha1"] = sha1  # sha1（仅file有值）
            intelligence_item["sha256"] = sha256  # sha256（仅file有值）
            try:
                intelligence_item["file_name"] = result["name"]  # 文件名称(file_name  仅file有值）
            except:
                intelligence_item["file_name"] = None
            try:
                intelligence_item["file_size"] = result["size"]  # 文件大小(file_size 仅file有值）
            except:
                intelligence_item["file_size"] = None
            try:
                intelligence_item["file_type"] = result["mimetype"]  # 文件类型(file_type 仅file有值）
            except:
                intelligence_item["file_type"] = None
            int_types, labels = cast_label(result["objectLabel"], label_dict)
            intelligence_item["intelligence_type"] = int_types
            intelligence_item["intelligence_credibility"] = result["x_opencti_score"]  # 情报可信度
            intelligence_item["is_label"] = len(labels) > 0  # 是否有评价标签
            intelligence_item["label"] = labels  # 情报标签数组
            intelligence_item["discovery_time"] = parse_date(result["created_at"])  # 发现时间
            intelligence_item["update_time"] = parse_date(result["updated_at"])  # 更新时间
            try:
                intelligence_item["is_revoked"] = result["indicators"][0]["revoked"]  # 是否过期 indicator revoked字段
            except:
                intelligence_item["is_revoked"] = None
            try:
                intelligence_item["source"] = result["createdBy"]["name"]  # 数据源
            except:
                intelligence_item["source"] = None

            intelligence_items.append(intelligence_item)

        intelligence_json_str = json.dumps(
            intelligence_items, indent=4, ensure_ascii=False
        )
        intelligence_detail.write(intelligence_json_str + "\n")


if __name__ == "__main__":
    output_json(
        file_name="intelligence_evaluation_100.json"
    )
