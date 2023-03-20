import json

import pandas as pd
import yaml
from pathlib import Path
from pycti import OpenCTIApiClient

from utils import load_label_dict


class QueryParams:
    def __init__(self, properties=None, types=None, filters=None):
        self.properties = properties
        self.types = types
        self.filters = filters


class BaseQuery:
    def __init__(self):
        config_path = Path(__file__).parent.joinpath("QueryConfig.yml")
        config = (
            yaml.load(config_path.open(), Loader=yaml.SafeLoader)
        )
        # 配置CTI连接
        config_opencti = config["opencti"]
        self.api_url = config_opencti['url']
        self.api_token = config_opencti['token']
        self.client = OpenCTIApiClient(self.api_url, self.api_token)

        config_files = config["files"]
        self.query_file_dic = config_files["query_dic"]
        self.query_file_name = None
        self.output_file_dic = config_files["output_dic"]
        self.output_file_name = None

        self.label_dict = load_label_dict()  # 加载标签映射字典

        # 查询参数
        self.query_params = QueryParams()
        self.set_query_params()

        # 加载需要查询的数据
        self.query_data = self.load_query_data()

    def load_query_data(self):
        if self.query_file_name is not None:
            query_file_path = Path(__file__).parent.joinpath(f"{self.query_file_dic}/{self.query_file_name}")
            df = pd.read_csv(query_file_path, sep=",")
        else:
            raise ValueError("query_file_name is not defined")
        return df.values

    def Query(self):
        results = self.Request()
        json_str = self.Produce(results)
        self.write_json(json_str)

    def Produce(self, results):
        items = []
        for result in results:
            item = self.doProduce(result)
            if item is not None:
                items.append(item)
        json_str = json.dumps(
            items, indent=4, ensure_ascii=False
        )
        return json_str

    def Request(self):
        raise NotImplementedError

    def doProduce(self, result):
        raise NotImplementedError

    def write_json(self, json_str):
        if self.output_file_name is not None:
            output_file_path = Path(__file__).parent.joinpath(f"{self.output_file_dic}/{self.output_file_name}")
            with open(output_file_path, "w", newline="\n", encoding="utf-8") as detail:
                detail.write(json_str + "\n")
        else:
            raise ValueError("output_file_name is not defined")

    def set_query_params(self):
        raise NotImplementedError


if __name__ == "__main__":
    Q = BaseQuery()
