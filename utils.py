from datetime import datetime, date
import pandas as pd
import unicodedata
from pandas import DataFrame


def list(opencti, **kwargs):
    properties = """
                id
                entity_type
                parent_types
                spec_version
                created_at
                updated_at
                standard_id
                relationship_type
                start_time
                stop_time
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
                    ... on StixCyberObservable {
                        id
                        standard_id
                        entity_type
                        parent_types
                        observable_value
                    }
                }
            """
    element_id = kwargs.get("elementId", None)
    from_id = kwargs.get("fromId", None)
    from_types = kwargs.get("fromTypes", None)
    to_id = kwargs.get("toId", None)
    to_types = kwargs.get("toTypes", None)
    relationship_type = kwargs.get("relationship_type", None)
    start_time_start = kwargs.get("startTimeStart", None)
    start_time_stop = kwargs.get("startTimeStop", None)
    stop_time_start = kwargs.get("stopTimeStart", None)
    stop_time_stop = kwargs.get("stopTimeStop", None)
    filters = kwargs.get("filters", [])
    first = kwargs.get("first", 500)
    after = kwargs.get("after", None)
    order_by = kwargs.get("orderBy", None)
    order_mode = kwargs.get("orderMode", None)
    custom_attributes = kwargs.get("customAttributes", None)
    get_all = kwargs.get("getAll", False)
    with_pagination = kwargs.get("withPagination", False)
    if get_all:
        first = 500

    opencti.log(
        "info",
        "Listing stix_observable_relationships with {type: "
        + str(relationship_type)
        + ", from_id: "
        + str(from_id)
        + ", to_id: "
        + str(to_id)
        + "}",
    )
    query = (
            """
            query StixCyberObservableRelationships($elementId: String, $fromId: StixRef, $fromTypes: [String], $toId: StixRef, $toTypes: [String], $relationship_type: [String], $startTimeStart: DateTime, $startTimeStop: DateTime, $stopTimeStart: DateTime, $stopTimeStop: DateTime, $filters: [StixCyberObservableRelationshipsFiltering], $first: Int, $after: ID, $orderBy: StixCyberObservableRelationshipsOrdering, $orderMode: OrderingMode) {
                stixCyberObservableRelationships(elementId: $elementId, fromId: $fromId, fromTypes: $fromTypes, toId: $toId, toTypes: $toTypes, relationship_type: $relationship_type, startTimeStart: $startTimeStart, startTimeStop: $startTimeStop, stopTimeStart: $stopTimeStart, stopTimeStop: $stopTimeStop, filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
                    edges {
                        node {
                            """
            + (custom_attributes if custom_attributes is not None else properties)
            + """
                    }
                }
                pageInfo {
                    startCursor
                    endCursor
                    hasNextPage
                    hasPreviousPage
                    globalCount
                }
            }
        }
     """
    )

    result = opencti.query(
        query,
        {
            "elementId": element_id,
            "fromId": from_id,
            "fromTypes": from_types,
            "toId": to_id,
            "toTypes": to_types,
            "relationship_type": relationship_type,
            "startTimeStart": start_time_start,
            "startTimeStop": start_time_stop,
            "stopTimeStart": stop_time_start,
            "stopTimeStop": stop_time_stop,
            "filters": filters,
            "first": first,
            "after": after,
            "orderBy": order_by,
            "orderMode": order_mode,
        },
    )
    return opencti.process_multiple(
        result["data"]["stixCyberObservableRelationships"], with_pagination
    )


def parse_date(text):
    if text in ['1970-01-01T00:00:00.000Z', '5138-11-16T09:46:40.000Z', None]:
        return None
    time_split = text.strip("Z").split("T")
    year, month, day = time_split[0].split("-")
    hour, minute, second = time_split[1].split(":")
    return date(
        int(year),
        int(month),
        int(day)).isoformat()


def parse_source_category(report_types):
    # 缺少公众号
    cate_dict = {
        "spider-flow": "技术博客",
        "spider": "技术博客",
        "threat-report": "厂商情报订阅"
    }
    return cate_dict[report_types]


def parse_ioc_type(cti_ioc_type):
    """
    将cti中的ioc类型转换成中资需要的类型
    :param cti_ioc_type: cti中的ioc类型
    :return: 中资需要的ioc类型
    """
    type_dict = {
        "Domain-Name": "ioc_domain",
        "StixFile": "ioc_md5",
        "URL": "ioc_url",
        "Email-Addr": "ioc_mail",
        "IPv4-Addr": "ioc_ipv4",
        "IPv6-Addr": "ioc_ipv6"
    }
    if cti_ioc_type in type_dict.keys():
        return type_dict[cti_ioc_type]
    return None


def reverse_ioc_type(ioc_type):
    """
    将中资的ioc类型转换成cti的ioc类型
    :param ioc_type: 将中资的ioc类型
    :return: cti的ioc类型
    """
    type_dict = {
        "ioc_domain": "Domain-Name",
        "Domain-ioc_md5": "StixFile",
        "ioc_url": "URL",
        "ioc_mail": "Email",
        "ioc_ipv4": "IPv4-Addr",
        "ioc_ipv6": "IPv6-Addr"
    }
    if ioc_type in type_dict.keys():
        return type_dict[ioc_type]
    return None


def parse_object_type(cti_object_type):
    type_dict = {
        "Domain-Name": "ioc_domain",
        "StixFile": "ioc_md5",
        "URL": "ioc_url",
        "Email-Addr": "ioc_mail",
        "IPv4-Addr": "ioc_ipv4",
        "IPv6-Addr": "ioc_ipv6",
        "Report": "report",
        "Malware": "malicious_family",
        "Intrusion-Set": "attack_organization"
    }
    if cti_object_type in type_dict.keys():
        return type_dict[cti_object_type]
    return None


def load_label_dict():
    excel_name = "标签映射/标签映射关系.xlsx"
    data = pd.read_excel(excel_name, sheet_name='0')
    label_dict = {}
    rows, cols = data.shape
    for i in range(rows):
        raw_label, label_type, standard_label = data.loc[i, :]
        label_dict[raw_label] = [label_type, standard_label]
    return label_dict


def cast_label(cti_labels, label_dict):
    labels = []
    int_types = []
    for label in cti_labels:
        raw_label = label["value"]
        if raw_label in label_dict.keys():
            labels.append(label_dict[raw_label][1])
            int_types.append(label_dict[raw_label][0])
    return int_types, labels


def load_query_data(query_file_name):
    """
    :param query_file_name: 查询文本的文件名
    :return: 读取到的查询文本，ndarry
    """
    df = pd.read_csv(query_file_name, sep=",")
    return df.values


def from_txt_to_list():
    file_path = 'country_name.txt'
    country_text = open(file_path, 'r', encoding='utf-8')
    # print(country_text)
    country_list = []
    for line in country_text.readlines():
        line = line.rstrip("\n")
        country_list.append(line)
    # print(country_list)
    return country_list


def get_all_country_CHN():
    country_list = from_txt_to_list()
    country_CHN = []
    for c in country_list:
        country_CHN.append(c.split(" : ")[0])
    return country_CHN


def is_chinese_char(char):
    """判断单个字符是否为中文"""
    return 'CJK' in unicodedata.name(char)


def is_chinese_string(string):
    """判断字符串是否全为中文"""
    for char in string:
        if not is_chinese_char(char):
            return False
    return True


if __name__ == '__main__':
    # load_label_dict()
    # load_query_data("Query text demo/IOC_text.csv")
    print(get_all_country_CHN())
