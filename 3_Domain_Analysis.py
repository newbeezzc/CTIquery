# coding: utf-8
import json
import re

from BaseQuery import BaseQuery
from utils import parse_date
import properties


class DomainAnalysisQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "DomainAnalysis_text.csv"
        self.output_file_name = "domain_analysis.json"

    def doRequest(self):
        """
        请求CTI，返回结果。
        :return: 查询CTI的结果
        """
        if self.query_params.Id is not None:
            return self.client.stix_core_relationship.list(
                relationship_type="resolves-to",
                fromId=self.query_params.Id,
                customAttributes=self.query_params.properties,
                fromTypes=self.query_params.types
            )
        else:
            return []

    def doProduce(self, result):
        item = dict()
        item["domain"] = result.get("from", {}).get("observable_value")  # 域名
        description = result.get("description", "")
        rrtype_value = None
        if description:
            rrtype_value = json.loads(description).get("rrtype")
        item["analysis_type"] = rrtype_value  # 解析类型
        item["discovery_time"] = parse_date(result.get("start_time"))  # 发现时间
        item["analytic_value"] = result.get("to", {}).get("observable_value")  # 解析值
        item["last_seen"] = parse_date(result.get("stop_time"))  # 最近发现时间

        return [item]

    def set_query_params(self, row_data):
        result = self.client.stix_cyber_observable.list(
            filters=[
                {"key": "value", "values": [row_data[0]]}
            ],
            types=["Domain-Name"]
        )
        self.query_params.properties = properties.DomainAnalysis_properties
        self.query_params.types = ["Domain-Name"]
        if result:
            self.query_params.Id = result[0].get("id")
        else:
            self.query_params.Id = None


if __name__ == "__main__":
    # s = "{\"rrtype\":\"A\"} "
    # js = json.loads(s)
    # print(js.get("rrtype"))

    q = DomainAnalysisQuery()
    q.Query()
