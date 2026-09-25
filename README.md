# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

延期实行会签制：协调员发起延期申请（新期限+理由）后，报告人和全部维护者分别会签；任何人反对即关闭申请、原保密期照旧；全部同意后须由另一位协调员复核（发起人不能复核自己的申请）才生效。会签期间报告摘要、受影响版本或修复计划被修改时，进行中的申请立即失效，需重新发起。报告详情展示每条申请的每人意见、当前待办人和新旧期限。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。延期会签覆盖：全票同意后由另一位协调员复核生效、任一反对关闭申请且期限不变、发起人自我复核被拒、修改摘要/版本/修复计划使会签失效、页面载荷展示每人意见与待办人。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/extension-requests`、`POST /api/extension-requests/{id}/vote`、`POST /api/extension-requests/{id}/review`
- `POST /api/reports/{id}/summary`、`POST /api/reports/{id}/versions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。
