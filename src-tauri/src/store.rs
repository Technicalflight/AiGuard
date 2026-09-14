//! SQLite 持久化：请求日志、审计事件、kv 配置。
//!
//! 隐私红线：绝不存储请求/响应原文，只存命中类型、位置统计与哈希。
//!
//! 审计事件走**后台写线程**：审计写入绝不阻塞请求/响应路径（写库失败只丢事件，
//! 不影响流量）。**清空审计会设置 cutoff** —— cutoff 之前还在队列里的事件会被
//! 丢弃，否则清空后旧事件会回写（清空按钮"看起来没用"的经典 bug 形态）。

use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// 请求日志条目（字段命名与前端 types / commands 保持一致）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: i64,
    /// ISO 8601 时间戳
    pub ts: String,
    pub host: String,
    pub path: String,
    /// 会话 key
    pub session: String,
    /// 命中类型 JSON 数组，如 ["PHONE","EMAIL"]
    pub kinds: String,
    /// 处理动作：mask / block / warn / passthrough
    pub action: String,
    /// 请求体哈希前 16 位
    pub req_hash: String,
    /// 是否被拦截（0/1）
    pub blocked: i64,
}

/// 审计事件行（防护信号的落库形态）。
///
/// `evidence` 必须是**已脱敏**的短描述（类型 / 长度 / 摘要），禁止原文。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventRow {
    #[serde(default)]
    pub seq: i64,
    /// Unix 秒（浮点，便于排序）
    pub ts: f64,
    /// 会话 id
    pub sid: String,
    pub host: String,
    pub method: String,
    pub path: String,
    /// 信号名（error_leak / identity_swap / ...）
    pub signal_type: String,
    /// LOW / MEDIUM / HIGH / CRITICAL
    pub severity: String,
    /// 已脱敏的短证据
    pub evidence: String,
    /// 请求体哈希前 16 位
    #[serde(default)]
    pub request_hash: String,
    /// 响应体哈希前 16 位
    #[serde(default)]
    pub response_hash: String,
    /// 主动核查 id（非核查流量为空）
    #[serde(default)]
    pub probe_id: String,
}

/// SQLite 存储封装（内部用 Mutex 保护连接）。
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// 打开（或创建）数据库并初始化表结构。
    pub fn open(path: &Path) -> Result<Store, String> {
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS request_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                session TEXT NOT NULL,
                kinds TEXT NOT NULL DEFAULT '[]',
                action TEXT NOT NULL DEFAULT 'mask',
                req_hash TEXT NOT NULL DEFAULT '',
                blocked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts);
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                sid TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                method TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                signal_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '',
                request_hash TEXT NOT NULL DEFAULT '',
                response_hash TEXT NOT NULL DEFAULT '',
                probe_id TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events(ts);
            CREATE INDEX IF NOT EXISTS idx_audit_events_signal ON audit_events(signal_type);
            CREATE INDEX IF NOT EXISTS idx_audit_events_probe ON audit_events(probe_id);
            CREATE TABLE IF NOT EXISTS kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            -- 旧防护体系的日志表已废弃，直接移除
            DROP TABLE IF EXISTS security_log;
            "#,
        )
        .map_err(|e| e.to_string())?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// 写入一条请求日志。
    pub fn log_request(
        &self,
        ts: &str,
        host: &str,
        path: &str,
        session: &str,
        kinds: &str,
        action: &str,
        req_hash: &str,
        blocked: bool,
    ) -> Result<i64, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO request_log (ts, host, path, session, kinds, action, req_hash, blocked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                ts,
                host,
                path,
                session,
                kinds,
                action,
                req_hash,
                blocked as i64
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(conn.last_insert_rowid())
    }

    /// 按时间倒序列出最近 n 条日志。
    pub fn list_requests(&self, limit: i64) -> Result<Vec<RequestLog>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, host, path, session, kinds, action, req_hash, blocked
                 FROM request_log ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![limit], |row| {
                Ok(RequestLog {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    host: row.get(2)?,
                    path: row.get(3)?,
                    session: row.get(4)?,
                    kinds: row.get(5)?,
                    action: row.get(6)?,
                    req_hash: row.get(7)?,
                    blocked: row.get(8)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// 分页列出请求日志（供请求页 / 审计页），返回 (当前页数据, 过滤后总条数)。
    ///
    /// - `action`：None = 全部；Some("mask") = 仅已脱敏；Some("block") = 已拦截（blocked=1 或 action='block'）
    /// - `from_ts` / `to_ts`：Unix 秒范围（左闭右开），None = 不限；ts 列为等长数字字符串，字典序即数值序
    pub fn list_requests_page(
        &self,
        offset: i64,
        limit: i64,
        action: Option<&str>,
        from_ts: Option<i64>,
        to_ts: Option<i64>,
    ) -> Result<(Vec<RequestLog>, i64), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut where_clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        match action {
            Some("mask") => where_clauses.push("action = 'mask'".to_string()),
            Some("block") => where_clauses.push("(blocked = 1 OR action = 'block')".to_string()),
            _ => {}
        }
        if let Some(f) = from_ts {
            params.push(Box::new(f.to_string()));
            where_clauses.push(format!("ts >= ?{}", params.len()));
        }
        if let Some(t) = to_ts {
            params.push(Box::new(t.to_string()));
            where_clauses.push(format!("ts < ?{}", params.len()));
        }
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        let total: i64 = {
            let sql = format!("SELECT COUNT(*) FROM request_log {}", where_sql);
            let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
            conn.query_row(&sql, refs.as_slice(), |r| r.get(0))
                .map_err(|e| e.to_string())?
        };

        params.push(Box::new(limit));
        params.push(Box::new(offset));
        let sql = format!(
            "SELECT id, ts, host, path, session, kinds, action, req_hash, blocked
             FROM request_log {} ORDER BY id DESC LIMIT ?{} OFFSET ?{}",
            where_sql,
            params.len() - 1,
            params.len()
        );
        let refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                Ok(RequestLog {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    host: row.get(2)?,
                    path: row.get(3)?,
                    session: row.get(4)?,
                    kinds: row.get(5)?,
                    action: row.get(6)?,
                    req_hash: row.get(7)?,
                    blocked: row.get(8)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok((out, total))
    }

    /// 按动作分类清理请求日志：各保留天数 `<= 0` = 永久保留。
    /// 返回 [直通删除数, 已脱敏删除数, 已拦截删除数]。直通记录通常设置最短的保留期（优先清理）。
    pub fn prune_request_logs(
        &self,
        now_secs: i64,
        passthrough_days: i64,
        mask_days: i64,
        block_days: i64,
    ) -> Result<[usize; 3], String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut removed = [0usize; 3];
        let groups: [(&str, i64, usize); 3] = [
            ("passthrough", passthrough_days, 0),
            ("mask", mask_days, 1),
            ("block", block_days, 2),
        ];
        for (action, days, idx) in groups {
            if days <= 0 {
                continue; // 永久保留
            }
            let cutoff = (now_secs - days.saturating_mul(86_400)).to_string();
            let n = conn
                .execute(
                    "DELETE FROM request_log WHERE action = ?1 AND ts < ?2",
                    rusqlite::params![action, cutoff],
                )
                .map_err(|e| e.to_string())?;
            removed[idx] = n;
        }
        Ok(removed)
    }

    /// 清空全部请求日志（所有动作类型）。返回删除条数。
    pub fn clear_request_logs(&self) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute("DELETE FROM request_log", [])
            .map_err(|e| e.to_string())
    }

    /// 清空指定动作类型的请求日志（passthrough / mask / block）。
    /// block 语义与筛选一致：blocked = 1 或 action = 'block'。
    pub fn clear_request_logs_by_action(&self, action: &str) -> Result<usize, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        if action == "block" {
            conn.execute(
                "DELETE FROM request_log WHERE blocked = 1 OR action = 'block'",
                [],
            )
            .map_err(|e| e.to_string())
        } else {
            conn.execute(
                "DELETE FROM request_log WHERE action = ?1",
                rusqlite::params![action],
            )
            .map_err(|e| e.to_string())
        }
    }

    /// 仪表盘统计：总请求数 / 已脱敏数 / 已拦截数 / 活跃会话数（按 session 去重）。
    pub fn stats(&self) -> Result<(i64, i64, i64, i64), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM request_log", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let scrubbed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM request_log WHERE action = 'mask'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        let blocked: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM request_log WHERE blocked = 1",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        let sessions: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT session) FROM request_log",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        Ok((total, scrubbed, blocked, sessions))
    }

    // ─────────────────────── 审计事件 ───────────────────────

    /// 批量写审计事件（单事务）。
    pub fn insert_audit_events(&self, rows: &[AuditEventRow]) -> Result<usize, String> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock().map_err(|e| e.to_string())?;
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let mut n = 0usize;
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO audit_events (ts, sid, host, method, path, signal_type, severity,
                                               evidence, request_hash, response_hash, probe_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .map_err(|e| e.to_string())?;
            for ev in rows {
                stmt.execute(rusqlite::params![
                    ev.ts,
                    ev.sid,
                    ev.host,
                    ev.method,
                    ev.path,
                    ev.signal_type,
                    ev.severity,
                    ev.evidence,
                    ev.request_hash,
                    ev.response_hash,
                    ev.probe_id
                ])
                .map_err(|e| e.to_string())?;
                n += 1;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(n)
    }

    /// 读取审计事件（since=返回 id 更大的；`severity_floor` 与 `signal_filter` 是
    /// **读侧**过滤——只影响展示，不删历史行）。核查归集与增量拉取使用。
    #[allow(dead_code)]
    pub fn fetch_audit_events(
        &self,
        since: i64,
        limit: i64,
        severity_floor: Option<&str>,
        signal_filter: Option<&str>,
    ) -> Result<Vec<AuditEventRow>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut where_clause = vec!["id > ?1".to_string()];
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(since)];
        if let Some(floor) = severity_floor {
            // CASE 计算严重度秩，避免加列
            let rank = match floor.trim().to_ascii_uppercase().as_str() {
                "CRITICAL" => 4,
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                _ => 0,
            };
            if rank > 0 {
                where_clause.push(format!(
                    "(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 \
                     WHEN 'MEDIUM' THEN 2 ELSE 1 END) >= {rank}"
                ));
            }
        }
        if let Some(sig) = signal_filter {
            if !sig.trim().is_empty() {
                params.push(Box::new(sig.to_string()));
                where_clause.push(format!("signal_type = ?{}", params.len()));
            }
        }
        // LIMIT 直接内联（clamp 后），不进参数列表
        let lim = limit.clamp(1, 1000);
        let sql = format!(
            "SELECT id, ts, sid, host, method, path, signal_type, severity, evidence, \
             request_hash, response_hash, probe_id FROM audit_events WHERE {} \
             ORDER BY id DESC LIMIT {}",
            where_clause.join(" AND "),
            lim
        );
        let mut stmt = conn.prepare(&sql).map_err(|e| e.to_string())?;
        let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                Ok(AuditEventRow {
                    seq: row.get(0)?,
                    ts: row.get(1)?,
                    sid: row.get(2)?,
                    host: row.get(3)?,
                    method: row.get(4)?,
                    path: row.get(5)?,
                    signal_type: row.get(6)?,
                    severity: row.get(7)?,
                    evidence: row.get(8)?,
                    request_hash: row.get(9)?,
                    response_hash: row.get(10)?,
                    probe_id: row.get(11)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        out.reverse(); // 由旧到新
        Ok(out)
    }

    /// 按 id 倒序列出（供核查归集）。
    pub fn fetch_audit_events_desc(&self, limit: i64) -> Result<Vec<AuditEventRow>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts, sid, host, method, path, signal_type, severity, evidence, \
                 request_hash, response_hash, probe_id FROM audit_events \
                 ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(rusqlite::params![limit], |row| {
                Ok(AuditEventRow {
                    seq: row.get(0)?,
                    ts: row.get(1)?,
                    sid: row.get(2)?,
                    host: row.get(3)?,
                    method: row.get(4)?,
                    path: row.get(5)?,
                    signal_type: row.get(6)?,
                    severity: row.get(7)?,
                    evidence: row.get(8)?,
                    request_hash: row.get(9)?,
                    response_hash: row.get(10)?,
                    probe_id: row.get(11)?,
                })
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// 删除早于保留期的审计事件。`retention_days <= 0` = 永久保留（不是「留一天」）。
    pub fn prune_audit_events(&self, retention_days: i64) -> Result<usize, String> {
        if retention_days <= 0 {
            return Ok(0);
        }
        let cutoff = now_secs_f64() - (retention_days as f64) * 86400.0;
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let n = conn
            .execute(
                "DELETE FROM audit_events WHERE ts < ?1",
                rusqlite::params![cutoff],
            )
            .map_err(|e| e.to_string())?;
        Ok(n)
    }

    /// 每个信号的命中计数（含 0 的项由调用方补齐）。
    pub fn audit_signal_counts(&self) -> Result<Vec<(String, i64)>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT signal_type, COUNT(*) FROM audit_events GROUP BY signal_type")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| e.to_string())?);
        }
        Ok(out)
    }

    /// 清空审计事件。返回 (删除行数, cutoff)。
    /// cutoff 会同步给写线程：清空后仍在队列里的更早事件会被丢弃（SHIELD-CLEAR-001）。
    pub fn clear_audit_events(&self) -> Result<(usize, f64), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let n = conn
            .execute("DELETE FROM audit_events", [])
            .map_err(|e| e.to_string())?;
        Ok((n, now_secs_f64()))
    }

    /// 读取 kv 配置。
    pub fn kv_get(&self, key: &str) -> Result<Option<String>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare("SELECT value FROM kv WHERE key = ?1")
            .map_err(|e| e.to_string())?;
        let mut rows = stmt
            .query(rusqlite::params![key])
            .map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let value: String = row.get(0).map_err(|e| e.to_string())?;
            return Ok(Some(value));
        }
        Ok(None)
    }

    /// 写入 kv 配置。
    pub fn kv_set(&self, key: &str, value: &str) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = ?2",
            rusqlite::params![key, value],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }
}

/// 当前 Unix 秒（浮点）。
pub fn now_secs_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ═══════════════════════ 后台审计写线程 ═══════════════════════

/// 审计事件异步写入口：流量路径只 `enqueue`，落库由独立线程批量完成。
///
/// 写线程持有**自己的**数据库连接（SQLite 多连接安全），与主连接互不阻塞。
pub struct AuditWriter {
    tx: mpsc::Sender<AuditEventRow>,
    /// 清空 cutoff：cutoff 之前还在队列里的事件会被丢弃
    cutoff: Arc<Mutex<f64>>,
    dropped: Arc<std::sync::atomic::AtomicU64>,
}

impl Clone for AuditWriter {
    fn clone(&self) -> Self {
        AuditWriter {
            tx: self.tx.clone(),
            cutoff: self.cutoff.clone(),
            dropped: self.dropped.clone(),
        }
    }
}

impl AuditWriter {
    /// 启动后台写线程（打开独立连接）。
    pub fn spawn(db_path: &Path) -> Result<AuditWriter, String> {
        let (tx, rx) = mpsc::channel::<AuditEventRow>();
        let store = Store::open(db_path)?;
        let cutoff: Arc<Mutex<f64>> = Arc::new(Mutex::new(0.0));
        let dropped = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cutoff_t = cutoff.clone();
        let dropped_t = dropped.clone();
        std::thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || {
                let mut batch: Vec<AuditEventRow> = Vec::new();
                loop {
                    // 批量窗口：攒 50ms 的事件一次写入，减少事务次数
                    match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                        Ok(ev) => batch.push(ev),
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    // 把通道里已有的排空（非阻塞）
                    while let Ok(ev) = rx.try_recv() {
                        batch.push(ev);
                    }
                    if batch.is_empty() {
                        continue;
                    }
                    let cut = match cutoff_t.lock() {
                        Ok(g) => *g,
                        Err(poisoned) => *poisoned.into_inner(),
                    };
                    batch.retain(|ev| ev.ts >= cut);
                    if batch.is_empty() {
                        continue;
                    }
                    if let Err(e) = store.insert_audit_events(&batch) {
                        // 写库失败：丢事件不影响流量，但计数留痕
                        dropped_t.fetch_add(
                            batch.len() as u64,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        log::warn!("审计事件写库失败（丢弃 {} 条）: {}", batch.len(), e);
                    }
                    batch.clear();
                }
            })
            .map_err(|e| format!("审计写线程启动失败: {}", e))?;
        Ok(AuditWriter {
            tx,
            cutoff,
            dropped,
        })
    }

    /// 入队一条审计事件（非阻塞）。
    pub fn enqueue(&self, ev: AuditEventRow) {
        // 尽力而为的有界队列语义：send 失败说明写线程已退出，事件丢弃
        let _ = self.tx.send(ev);
    }

    /// 设置清空 cutoff（清空审计后，队列中更早的事件将被丢弃）。
    pub fn set_cutoff(&self, ts: f64) {
        match self.cutoff.lock() {
            Ok(mut c) => *c = ts,
            Err(poisoned) => *poisoned.into_inner() = ts,
        }
    }

    /// 累计丢弃数（诊断用；当前实现为写入失败计数）。
    #[allow(dead_code)]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aiguard_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn row(ts: f64, signal: &str, sev: &str, check: &str) -> AuditEventRow {
        AuditEventRow {
            seq: 0,
            ts,
            sid: "s1".into(),
            host: "api.openai.com".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            signal_type: signal.into(),
            severity: sev.into(),
            evidence: format!("{}: len=29 sha256=abcd1234ef567890", signal),
            request_hash: "req123".into(),
            response_hash: "resp456".into(),
            probe_id: check.into(),
        }
    }

    #[test]
    fn test_store_roundtrip() {
        let dir = tmp_dir();
        let store = Store::open(&dir.join("test.db")).unwrap();
        store
            .log_request(
                "2025-01-01T00:00:00Z",
                "api.openai.com",
                "/v1/chat/completions",
                "127.0.0.1:12345",
                r#"["PHONE"]"#,
                "mask",
                "abcdef1234567890",
                false,
            )
            .unwrap();
        let logs = store.list_requests(10).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].kinds, r#"["PHONE"]"#);
        let (total, scrubbed, blocked, sessions) = store.stats().unwrap();
        assert_eq!((total, scrubbed, blocked, sessions), (1, 1, 0, 1));

        store.kv_set("rule.phone.enabled", "false").unwrap();
        assert_eq!(
            store.kv_get("rule.phone.enabled").unwrap().as_deref(),
            Some("false")
        );
        assert_eq!(store.kv_get("missing.key").unwrap(), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_events_insert_and_fetch_with_floor() {
        let dir = tmp_dir();
        let store = Store::open(&dir.join("test.db")).unwrap();
        store
            .insert_audit_events(&[
                row(100.0, "sse_anomaly", "LOW", ""),
                row(101.0, "response_poison", "MEDIUM", ""),
                row(102.0, "error_leak", "CRITICAL", ""),
                row(103.0, "cross_request_pollution", "HIGH", "probe_x"),
            ])
            .unwrap();

        // 不过滤：全部按旧→新
        let all = store.fetch_audit_events(0, 100, None, None).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].signal_type, "sse_anomaly");

        // floor=MEDIUM：LOW 被挡在默认视图外
        let med = store.fetch_audit_events(0, 100, Some("MEDIUM"), None).unwrap();
        assert_eq!(med.len(), 3);
        assert!(med.iter().all(|r| r.severity != "LOW"));

        // 信号过滤
        let only = store
            .fetch_audit_events(0, 100, None, Some("cross_request_pollution"))
            .unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].probe_id, "probe_x");

        // since 增量（id > 3：只剩最后一条）
        let inc = store.fetch_audit_events(3, 100, None, None).unwrap();
        assert_eq!(inc.len(), 1);
        assert_eq!(inc[0].signal_type, "cross_request_pollution");
        assert_eq!(inc[0].seq, 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_prune_zero_means_forever() {
        let dir = tmp_dir();
        let store = Store::open(&dir.join("test.db")).unwrap();
        store
            .insert_audit_events(&[row(1.0, "error_leak", "HIGH", "")])
            .unwrap();
        // 0 = 永久保留
        assert_eq!(store.prune_audit_events(0).unwrap(), 0);
        assert_eq!(
            store.fetch_audit_events(0, 10, None, None).unwrap().len(),
            1
        );
        // 7 天保留：ts=1（1970 年）必然被清
        assert_eq!(store.prune_audit_events(7).unwrap(), 1);
        assert!(store
            .fetch_audit_events(0, 10, None, None)
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_writer_batch_and_cutoff() {
        let dir = tmp_dir();
        let db = dir.join("test.db");
        let store = Store::open(&db).unwrap();
        let writer = AuditWriter::spawn(&db).unwrap();
        for i in 0..5 {
            writer.enqueue(row(200.0 + i as f64, "error_leak", "HIGH", ""));
        }
        // 等 writer 批量落库
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert_eq!(
            store.fetch_audit_events(0, 10, None, None).unwrap().len(),
            5,
            "队列事件应被批量写入"
        );
        // 清空 + cutoff：队列里更早的事件应被丢弃
        let (n, cut) = store.clear_audit_events().unwrap();
        assert_eq!(n, 5);
        writer.set_cutoff(cut);
        writer.enqueue(row(cut - 10.0, "error_leak", "HIGH", ""));
        writer.enqueue(row(cut + 10.0, "response_poison", "MEDIUM", ""));
        std::thread::sleep(std::time::Duration::from_millis(250));
        let rows = store.fetch_audit_events(0, 10, None, None).unwrap();
        assert_eq!(
            rows.len(),
            1,
            "cutoff 之前的队列事件必须被丢弃: {:?}",
            rows
        );
        assert_eq!(rows[0].signal_type, "response_poison");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_audit_signal_counts() {
        let dir = tmp_dir();
        let store = Store::open(&dir.join("test.db")).unwrap();
        store
            .insert_audit_events(&[
                row(1.0, "error_leak", "HIGH", ""),
                row(2.0, "error_leak", "HIGH", ""),
                row(3.0, "sse_anomaly", "LOW", ""),
            ])
            .unwrap();
        let counts = store.audit_signal_counts().unwrap();
        assert_eq!(
            counts
                .iter()
                .find(|(s, _)| s == "error_leak")
                .map(|(_, n)| *n),
            Some(2)
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
