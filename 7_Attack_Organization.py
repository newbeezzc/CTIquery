# coding: utf-8
import json
import re

from BaseQuery import BaseQuery
from utils import parse_date, get_all_country_CHN, is_chinese_string
import properties


class AttackOrganizationQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "AttackOrganization_text.csv"
        self.output_file_name = "attack_organization.json"

    def doRequest(self):
        """
        请求CTI，返回结果。
        :return: 查询CTI的结果
        """
        return self.client.intrusion_set.list(
            customAttributes=self.query_params.properties,
            filters=self.query_params.filters
        )

    def doProduce(self, result):
        item = dict()
        item["organization_id"] = result.get("id")  # 组织唯一ID
        item["organization_name"] = result.get("name")  # 组织名称
        item["internal_number"] = None  # 内部编号（空值）
        item["aliases"] = result.get("aliases")  # 别名
        item["organization_introduction"] = result.get("description")  # 组织介绍
        item["organization_type"] = result.get("resource_level")  # 组织类型
        item["discovery_time"] = parse_date(result.get("first_seen"))  # 发现时间
        item["last_active_time"] = parse_date(result.get("last_seen"))  # 最近活跃时间
        locations = []
        industry = []
        country = []
        pattern = []
        if result.get("stixCoreRelationships", []):
            for relation in result["stixCoreRelationships"]:
                relation_type = relation.get("relationship_type")
                if not relation.get("to"):
                    continue
                to_entity_type = relation["to"].get("entity_type")
                if relation_type == "originates-from":
                    locations.append(relation["to"].get("name"))
                elif relation_type == "targets":
                    if to_entity_type == "Sector":
                        industry.append(relation["to"].get("name"))
                    elif to_entity_type == "Country":
                        country.append(relation["to"].get("name"))
                elif relation_type == "uses":
                    if to_entity_type == "Attack-Pattern":
                        pattern.append(relation["to"].get("name"))

        item["organization_location"] = locations  # 组织位置
        item["target_industry"] = industry  # 目标行业
        item["target_countries/regions"] = country  # 目标国家、地区
        item["language"] = result.get("lang")  # 常用语言
        item["source"] = "爬虫"  # 情报来源(爬虫) result["createdBy"]
        item["attack_mode"] = pattern  # 攻击方式

        return [item]

    def set_query_params(self, row_data):
        self.query_params.properties = properties.AttackOrganization_properties
        self.query_params.filters = [{"key": "name", "values": row_data[0]}]


if __name__ == "__main__":
    q = AttackOrganizationQuery()
    q.Query()
