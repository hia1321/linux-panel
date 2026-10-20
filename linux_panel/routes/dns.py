from flask import Blueprint
from ..core import *


bp = Blueprint("dns", __name__)

# ============================================================================
# 域名解析管理 (DNS)
# ============================================================================
@bp.route("/api/dns/accounts", methods=["GET", "POST"])
@login_required
def api_dns_accounts():
    if request.method == "GET":
        rows = db_all("SELECT id, provider, name, created_at FROM dns_accounts ORDER BY id DESC")
        return jsonify(code=0, data=rows)
    d = request.get_json() or {}
    provider = d.get("provider")
    name = (d.get("name") or "").strip()
    config = d.get("config") or {}
    if not provider or not name or not config:
        return jsonify(code=400, msg="参数不完整")
    now = datetime.now().isoformat(timespec="seconds")
    db_exec("INSERT INTO dns_accounts (provider, name, config_json, created_at) VALUES (?,?,?,?)",
            (provider, name, json.dumps(config), now))
    return jsonify(code=0, msg="账号添加成功")

@bp.route("/api/dns/accounts/<int:aid>", methods=["DELETE"])
@login_required
def api_dns_account_delete(aid):
    db_exec("DELETE FROM dns_accounts WHERE id=?", (aid,))
    return jsonify(code=0, msg="已删除")

@bp.route("/api/dns/domains")
@login_required
def api_dns_domains():
    aid = request.args.get("account_id")
    acc = db_one("SELECT * FROM dns_accounts WHERE id=?", (aid,))
    if not acc: return jsonify(code=400, msg="账号不存在")
    config = json.loads(acc["config_json"])
    domains = []
    try:
        if acc["provider"] == "cloudflare":
            headers = {"Authorization": f"Bearer {config.get('token')}", "Content-Type": "application/json"}
            r = requests.get("https://api.cloudflare.com/client/v4/zones?per_page=100", headers=headers, timeout=10).json()
            if r.get("success"):
                for z in r.get("result", []):
                    domains.append({"id": z["id"], "name": z["name"]})
        elif acc["provider"] == "aliyun":
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkalidns.request.v20150109.DescribeDomainsRequest import DescribeDomainsRequest
            client = AcsClient(config.get("access_key"), config.get("access_secret"), "cn-hangzhou")
            req = DescribeDomainsRequest()
            req.set_accept_format('json')
            resp = json.loads(client.do_action_with_exception(req))
            for d in resp.get("Domains", {}).get("Domain", []):
                domains.append({"id": d["DomainName"], "name": d["DomainName"]})
        elif acc["provider"] == "tencent":
            from tencentcloud.common import credential
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.dnspod.v20210323 import dnspod_client, models
            
            cred = credential.Credential(config.get("secret_id"), config.get("secret_key"))
            httpProfile = HttpProfile(); httpProfile.endpoint = "dnspod.tencentcloudapi.com"
            clientProfile = ClientProfile(); clientProfile.httpProfile = httpProfile
            client = dnspod_client.DnspodClient(cred, "", clientProfile)
            req = models.DescribeDomainListRequest()
            resp = json.loads(client.DescribeDomainList(req).to_json_string())
            for d in resp.get("DomainList", []):
                domains.append({"id": d["Domain"], "name": d["Domain"]})
        else:
            return jsonify(code=400, msg="该厂商暂未实现")
    except Exception as e:
        return jsonify(code=500, msg=f"获取失败: {e}")
    return jsonify(code=0, data=domains)

@bp.route("/api/dns/records", methods=["GET", "POST"])
@login_required
def api_dns_records():
    if request.method == "GET":
        aid = request.args.get("account_id")
        domain = request.args.get("domain")
        acc = db_one("SELECT * FROM dns_accounts WHERE id=?", (aid,))
        if not acc: return jsonify(code=400, msg="账号不存在")
        config = json.loads(acc["config_json"])
        records = []
        try:
            if acc["provider"] == "cloudflare":
                headers = {"Authorization": f"Bearer {config.get('token')}", "Content-Type": "application/json"}
                zones = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers, timeout=10).json()
                zone_id = next((z["id"] for z in zones.get("result", []) if z["name"] == domain), None)
                if zone_id:
                    r = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100", headers=headers, timeout=10).json()
                    if r.get("success"):
                        for rec in r.get("result", []):
                            records.append({"id": rec["id"], "name": rec["name"].replace(f".{domain}", ""), "type": rec["type"], "content": rec["content"], "ttl": rec["ttl"]})
            elif acc["provider"] == "aliyun":
                from aliyunsdkcore.client import AcsClient
                from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
                client = AcsClient(config.get("access_key"), config.get("access_secret"), "cn-hangzhou")
                req = DescribeDomainRecordsRequest()
                req.set_accept_format('json')
                req.set_DomainName(domain)
                resp = json.loads(client.do_action_with_exception(req))
                for rec in resp.get("DomainRecords", {}).get("Record", []):
                    records.append({"id": rec["RecordId"], "name": rec["RR"], "type": rec["Type"], "content": rec["Value"], "ttl": rec["TTL"]})
            elif acc["provider"] == "tencent":
                from tencentcloud.common import credential
                from tencentcloud.common.profile.client_profile import ClientProfile
                from tencentcloud.common.profile.http_profile import HttpProfile
                from tencentcloud.dnspod.v20210323 import dnspod_client, models
                cred = credential.Credential(config.get("secret_id"), config.get("secret_key"))
                httpProfile = HttpProfile(); httpProfile.endpoint = "dnspod.tencentcloudapi.com"
                clientProfile = ClientProfile(); clientProfile.httpProfile = httpProfile
                client = dnspod_client.DnspodClient(cred, "", clientProfile)
                req = models.DescribeRecordListRequest()
                req.Domain = domain
                resp = json.loads(client.DescribeRecordList(req).to_json_string())
                for rec in resp.get("RecordList", []):
                    records.append({"id": str(rec["RecordId"]), "name": rec["Name"], "type": rec["Type"], "content": rec["Value"], "ttl": rec["TTL"]})
        except Exception as e:
            return jsonify(code=500, msg=f"获取失败: {e}")
        return jsonify(code=0, data=records)

    d = request.get_json() or {}
    aid, domain, r_type, name, content = d.get("account_id"), d.get("domain"), d.get("type"), d.get("name"), d.get("content")
    acc = db_one("SELECT * FROM dns_accounts WHERE id=?", (aid,))
    if not acc: return jsonify(code=400, msg="账号不存在")
    config = json.loads(acc["config_json"])
    try:
        if acc["provider"] == "cloudflare":
            headers = {"Authorization": f"Bearer {config.get('token')}", "Content-Type": "application/json"}
            zones = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers, timeout=10).json()
            zone_id = next((z["id"] for z in zones.get("result", []) if z["name"] == domain), None)
            full_name = f"{name}.{domain}" if name != "@" else domain
            payload = {"type": r_type, "name": full_name, "content": content, "ttl": 120, "proxied": False}
            requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers, json=payload, timeout=10)
        elif acc["provider"] == "aliyun":
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
            client = AcsClient(config.get("access_key"), config.get("access_secret"), "cn-hangzhou")
            req = AddDomainRecordRequest()
            req.set_accept_format('json')
            req.set_DomainName(domain)
            req.set_RR(name)
            req.set_Type(r_type)
            req.set_Value(content)
            client.do_action_with_exception(req)
        elif acc["provider"] == "tencent":
            from tencentcloud.common import credential
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.dnspod.v20210323 import dnspod_client, models
            cred = credential.Credential(config.get("secret_id"), config.get("secret_key"))
            httpProfile = HttpProfile(); httpProfile.endpoint = "dnspod.tencentcloudapi.com"
            clientProfile = ClientProfile(); clientProfile.httpProfile = httpProfile
            client = dnspod_client.DnspodClient(cred, "", clientProfile)
            req = models.CreateRecordRequest()
            req.Domain = domain
            req.SubDomain = name
            req.RecordType = r_type
            req.RecordLine = "默认"
            req.Value = content
            client.CreateRecord(req)
    except Exception as e:
        return jsonify(code=500, msg=f"添加失败: {e}")
    return jsonify(code=0, msg="添加成功")

@bp.route("/api/dns/records/<rid>", methods=["DELETE"])
@login_required
def api_dns_record_delete(rid):
    aid, domain = request.args.get("account_id"), request.args.get("domain")
    acc = db_one("SELECT * FROM dns_accounts WHERE id=?", (aid,))
    if not acc: return jsonify(code=400, msg="账号不存在")
    config = json.loads(acc["config_json"])
    try:
        if acc["provider"] == "cloudflare":
            headers = {"Authorization": f"Bearer {config.get('token')}", "Content-Type": "application/json"}
            zones = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers, timeout=10).json()
            zone_id = next((z["id"] for z in zones.get("result", []) if z["name"] == domain), None)
            if zone_id: requests.delete(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}", headers=headers, timeout=10)
        elif acc["provider"] == "aliyun":
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkalidns.request.v20150109.DeleteDomainRecordRequest import DeleteDomainRecordRequest
            client = AcsClient(config.get("access_key"), config.get("access_secret"), "cn-hangzhou")
            req = DeleteDomainRecordRequest()
            req.set_accept_format('json')
            req.set_RecordId(rid)
            client.do_action_with_exception(req)
        elif acc["provider"] == "tencent":
            from tencentcloud.common import credential
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.dnspod.v20210323 import dnspod_client, models
            cred = credential.Credential(config.get("secret_id"), config.get("secret_key"))
            httpProfile = HttpProfile(); httpProfile.endpoint = "dnspod.tencentcloudapi.com"
            clientProfile = ClientProfile(); clientProfile.httpProfile = httpProfile
            client = dnspod_client.DnspodClient(cred, "", clientProfile)
            req = models.DeleteRecordRequest()
            req.Domain = domain
            req.RecordId = int(rid)
            client.DeleteRecord(req)
    except Exception as e:
        return jsonify(code=500, msg=f"删除失败: {e}")
    return jsonify(code=0, msg="删除成功")



@bp.route("/api/dns/records/<rid>", methods=["PUT"])
@login_required
def api_dns_record_update(rid):
    d = request.get_json() or {}
    aid, domain, r_type, name, content = d.get("account_id"), d.get("domain"), d.get("type"), d.get("name"), d.get("content")
    acc = db_one("SELECT * FROM dns_accounts WHERE id=?", (aid,))
    if not acc: return jsonify(code=400, msg="账号不存在")
    config = json.loads(acc["config_json"])
    try:
        if acc["provider"] == "cloudflare":
            headers = {"Authorization": f"Bearer {config.get('token')}", "Content-Type": "application/json"}
            zones = requests.get("https://api.cloudflare.com/client/v4/zones", headers=headers, timeout=10).json()
            zone_id = next((z["id"] for z in zones.get("result", []) if z["name"] == domain), None)
            if not zone_id: return jsonify(code=400, msg="找不到域名对应的Zone ID")
            full_name = f"{name}.{domain}" if name != "@" else domain
            payload = {"type": r_type, "name": full_name, "content": content, "ttl": 120, "proxied": False}
            r = requests.put(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{rid}", headers=headers, json=payload, timeout=10).json()
            if not r.get("success"):
                return jsonify(code=500, msg=str(r.get("errors")))
                
        elif acc["provider"] == "aliyun":
            from aliyunsdkcore.client import AcsClient
            from aliyunsdkalidns.request.v20150109.UpdateDomainRecordRequest import UpdateDomainRecordRequest
            client = AcsClient(config.get("access_key"), config.get("access_secret"), "cn-hangzhou")
            req = UpdateDomainRecordRequest()
            req.set_accept_format('json')
            req.set_RecordId(rid)
            req.set_RR(name)
            req.set_Type(r_type)
            req.set_Value(content)
            client.do_action_with_exception(req)
            
        elif acc["provider"] == "tencent":
            from tencentcloud.common import credential
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.dnspod.v20210323 import dnspod_client, models
            cred = credential.Credential(config.get("secret_id"), config.get("secret_key"))
            httpProfile = HttpProfile(); httpProfile.endpoint = "dnspod.tencentcloudapi.com"
            clientProfile = ClientProfile(); clientProfile.httpProfile = httpProfile
            client = dnspod_client.DnspodClient(cred, "", clientProfile)
            req = models.ModifyRecordRequest()
            req.Domain = domain
            req.RecordId = int(rid)
            req.SubDomain = name
            req.RecordType = r_type
            req.RecordLine = "默认"
            req.Value = content
            client.ModifyRecord(req)
            
        else:
            return jsonify(code=400, msg="该厂商暂不支持修改")
    except Exception as e:
        return jsonify(code=500, msg=f"修改失败: {e}")
    return jsonify(code=0, msg="修改成功")
