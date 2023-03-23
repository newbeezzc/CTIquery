# coding: utf-8
import json
import re

from BaseQuery import BaseQuery
from utils import parse_date, get_all_country_CHN, is_chinese_string
import properties


class IPAddressQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "IPAddress_text.csv"
        self.output_file_name = "ip_address.json"
        self.country_list = get_all_country_CHN()

    def doRequest(self):
        """
        请求CTI，返回结果。
        :return: 查询CTI的结果
        """

        return self.client.stix_cyber_observable.list(
            customAttributes=self.query_params.properties,
            types=self.query_params.types,
            filters=self.query_params.filters
        )

    def doRequest_relation(self, IP_id):
        return self.client.stix_core_relationship.list(
            relationship_type=["located-at", "belongs-to"],
            fromId=IP_id,
            customAttributes=properties.IPAddressRelation_properties,
            fromTypes=["IPv4-Addr", "IPv6-Addr"],
            toTypes=["Country", "City", "Autonomous-System"]
        )

    def doProduce(self, result):
        item = dict()
        item["ip"] = result.get("observable_value")  # IP
        item["ip_type"] = result.get("entity_type")  # IP类型

        IP_id = result.get("id")
        relations = self.doRequest_relation(IP_id)
        country = None
        province = None
        city = None
        AS_name = None
        ASN = None
        latitude = None
        longitude = None

        for relation in relations:
            relation_type = relation.get("relationship_type")
            to_entity = relation.get("to", {})
            to_entity_type = to_entity.get("entity_type")

            if relation_type == "located-at":
                if to_entity_type == "Country":
                    # 如果不在国家列表里则是省 PS：cti在更高版本添加了Administrative_area实体
                    name_tmp = to_entity.get("name")
                    if name_tmp not in self.country_list and is_chinese_string(name_tmp):
                        province = name_tmp
                        if city is None or (longitude is None and latitude is None):
                            latitude = to_entity.get("latitude")
                            longitude = to_entity.get("longitude")
                    else:
                        country = name_tmp
                        if longitude is None and latitude is None:
                            latitude = to_entity.get("latitude")
                            longitude = to_entity.get("longitude")

                elif to_entity_type == "City":
                    city = to_entity.get("name")
                    latitude = to_entity.get("latitude")
                    longitude = to_entity.get("longitude")
            if relation_type == "belongs-to" and to_entity_type == "Autonomous-System":
                AS_name = to_entity.get("observable_value")
                ASN = to_entity.get("number")

        item["country"] = country  # 国家
        item["province/state"] = province  # 省份/州
        item["city"] = city  # 城市
        item["AS_organization_name"] = AS_name  # AS组织名称
        item["ASN"] = ASN  # ASN
        item["latitude"] = latitude  # 纬度
        item["longitude"] = longitude  # 经度

        return [item]

    def set_query_params(self, row_data):
        self.query_params.properties = properties.IPAddress_properties
        self.query_params.types = ["IPv4-Addr", "IPv6-Addr"]
        self.query_params.filters = [{"key": "value", "values": row_data[0]}]


if __name__ == "__main__":
    q = IPAddressQuery()
    q.Query()
