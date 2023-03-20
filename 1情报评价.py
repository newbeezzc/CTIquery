# coding: utf-8
from BaseQuery import BaseQuery
from utils import parse_date, parse_ioc_type, cast_label
import properties


class IOCQuery(BaseQuery):
    def __init__(self):
        super().__init__()
        self.query_file_name = "IOC_text.csv"
        self.output_file_name = "intelligence_evaluation.json"

    def Request(self):
        """
        请求CTI，返回结果。
        :return: 查询CTI的结果
        """
        # TODO:检查filter的使用
        return self.client.stix_cyber_observable.list(
            filters=self.query_params.filters,
            customAttributes=self.query_params.properties,
            types=self.query_params.types
        )

    def doProduce(self, result):
        item = dict()
        item["ioc"] = result.get("observable_value")  # ioc
        item["ioc_type"] = parse_ioc_type(result.get("entity_type"))  # ioc类型
        item["malicious_evaluation"] = result.get("x_opencti_description")  # 恶意评价
        item["highest_intelligence_credibility"] = result.get("x_opencti_score")  # 最高情报可信度
        sha1 = None
        sha256 = None
        hasMD5 = False
        for hash in result.get("hashes"):
            if hash["algorithm"] == 'MD5':
                item["ioc"] = hash.get("hash")
                hasMD5 = True
            elif hash["algorithm"] == 'SHA-1':
                sha1 = hash.get("hash")
            elif hash["algorithm"] == 'SHA-256':
                sha256 = hash.get("hash")
        if result["entity_type"] == "StixFile" and not hasMD5:  # 如果是文件但没有MD5则跳过
            return None
        item["sha1"] = sha1  # sha1（仅file有值）
        item["sha256"] = sha256  # sha256（仅file有值）
        item["file_name"] = result.get("name")  # 文件名称(file_name  仅file有值）
        item["file_size"] = result.get("size")  # 文件大小(file_size 仅file有值）
        item["file_type"] = result.get("mimetype")  # 文件类型(file_type 仅file有值）
        int_types, labels = cast_label(result.get("objectLabel"), self.label_dict)
        item["intelligence_type"] = int_types
        item["intelligence_credibility"] = result.get("x_opencti_score")  # 情报可信度
        item["is_label"] = bool(labels)  # 是否有评价标签
        item["label"] = labels  # 情报标签数组
        item["discovery_time"] = parse_date(result.get("created_at"))  # 发现时间
        item["update_time"] = parse_date(result.get("updated_at"))  # 更新时间
        item["is_revoked"] = result.get("indicators", [])[0].get("revoked")  # 是否过期 indicator revoked字段
        item["source"] = result.get("createdBy", {}).get("name")  # 数据源

        return item

    def set_query_params(self):
        self.query_params.properties = properties.IOC_properties
        self.query_params.types = ["Domain-Name", "StixFile", "URL", "Email-Addr", "IPv4-Addr", "IPv6-Addr"]
        self.query_params.filters = [{"key": "value", "values": "195.20.50.201", "filterMode": "and"}]


if __name__ == "__main__":
    # output_json(
    #     query_file_name="查询文本demo/IOC_text.csv",
    #     output_file_name="intelligence_evaluation_100.json"
    # )
    IOC_query = IOCQuery()
    IOC_query.Query()
