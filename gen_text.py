"""
生成测试所用数据
"""
import ujson
import pandas as pd


def gen_IOC():
    file_name = "Query text demo/IOCRelation_text.csv"
    json_path = "数据查询反馈及示例/"
    IOC_json = "2_Relation_Analysis_100.json"
    output_datas = []

    with open(json_path + IOC_json, 'r', encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            ioc = data["IOC"]
            ioc_type = data["IOC_type"]
            output_data = [ioc, ioc_type]
            output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(file_name, header=False, index=False)


def gen_Domain():
    file_name = "Query text demo/DomainAnalysis_text.csv"
    json_path = "数据查询反馈及示例/"
    json = "3_Domain_Analysis_100.json"
    output_datas = []

    with open(json_path + json, 'r', encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            domain = data["domain"]
            output_data = [domain]
            output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(file_name, header=False, index=False)


def gen_IP():
    file_name = "Query text demo/IPAddress_text.csv"
    json_path = "数据查询反馈及示例/"
    json = "5_IPAddr_500.json"
    output_datas = []

    with open(json_path + json, 'r', encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            domain = data["IP"]
            output_data = [domain]
            output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(file_name, header=False, index=False)


def gen_Ins():
    file_name = "Query text demo/AttackOrganization_text.csv"
    json_path = "数据查询反馈及示例/"
    json = "7_organization_180.json"
    output_datas = []

    with open(json_path + json, 'r', encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            domain = data["organization_name"]
            output_data = [domain]
            output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(file_name, header=False, index=False)


def gen_Mal():
    file_name = "Query text demo/MaliciousFamily_text.csv"
    json_path = "数据查询反馈及示例/"
    json = "8_malware_100.json"
    output_datas = []

    with open(json_path + json, 'r', encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            domain = data["malware_name"]
            output_data = [domain]
            output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(file_name, header=False, index=False)


def gen_report():
    file_name = "Query text demo/Report_text.csv"
    json_path = "数据查询反馈及示例/"
    json = "9_report_100.json"
    output_datas = []
    # TODO: 生成时间
    with open(json_path + json, 'r', encoding='utf-8') as f:
        datas = ujson.load(f)
        for data in datas:
            domain = data["report_time"]
            output_data = [domain]
            if output_data not in output_datas:
                output_datas.append(output_data)
        f.close()

    df = pd.DataFrame(data=output_datas)
    df.to_csv(file_name, header=False, index=False)


if __name__ == "__main__":
    # gen_IOC()
    # gen_Domain()
    # gen_IP()
    # gen_Ins()
    # gen_Mal()
    gen_report()
