# -*- coding: utf-8 -*-
"""
Retrieval Module
Contains document chunk cache, save_document_chunks, and context retrieval logic.
Decoupled from app.py to prevent circular dependencies.
"""

import os
import re
import json
import threading

# ── MODULE-LEVEL COMPILED REGEXES (compiled once, not per call) ───────────────
# Matches numbered section/clause headings and bullet/dash/asterisk list starters.
_SECTION_START_RE = re.compile(r'^(?:\d+\.\d+|\d+\.\d+\.\d+|\d+\.)\b|^\s*[\u2022\t\-\*]\s')
# Matches leading section numbers like "5.1", "Clause 5.1", etc.
_HEADER_RE = re.compile(r'^\s*(?:Clause\s+|Section\s+)?(\d+(?:\.\d+)*)\b', re.IGNORECASE)
import requests
import hashlib
import concurrent.futures
from src.db.database import SessionLocal, DocumentChunk, force_master

# Global cache for chunks ingested during upload processing
_ingested_chunks_cache = {}


def _cache_key(filename):
    """Thread-scoped key for _ingested_chunks_cache. extract_text() (doc_parsers.py)
    and save_document_chunks() below always run sequentially on the SAME thread for
    one upload, but the cache dict itself is process-wide/shared. Keying by filename
    alone let two concurrent uploads of an identically-named file (different audit
    sessions, different threads) overwrite each other's entry before it was read back
    -- e.g. one session's parsed document content getting saved into another
    session's report. Scoping by thread id makes that collision impossible: no other
    thread can ever write or read this thread's own entry."""
    return (threading.get_ident(), filename)

import pickle
CACHE_FILE = os.path.join(os.path.dirname(__file__), ".embeddings_cache.pkl")
_chunk_embeddings_cache = {}


def _embed_cache_key(filename, chunk_index, content):
    """Content-addressed key for the persistent _chunk_embeddings_cache (which is
    pickled to disk and shared across every session/audit, not just one). Keying
    by (filename, chunk_index) alone isn't safe across different sessions: two
    unrelated sessions can each have a same-named file whose chunk at the same
    index holds completely different content, and that key alone can't tell them
    apart -- silently scoring one session's chunk against a stale, wrong-content
    cached embedding vector when the native vector engine is unavailable and the
    Python-cosine fallback runs. Including a content hash makes this genuinely
    content-addressed: identical content anywhere (e.g. a standard NDA template
    reused across audits) still correctly shares one cached embedding, while
    different content under a coincidentally same-named file/index gets its own
    entry instead of colliding.
    """
    content_hash = hashlib.md5((content or "").encode("utf-8", errors="ignore")).hexdigest()[:12]
    return (filename, chunk_index, content_hash)
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "rb") as f:
            _chunk_embeddings_cache = pickle.load(f)
        print(f"[EMBEDDING CACHE] Loaded {len(_chunk_embeddings_cache)} persistent embeddings from cache.", flush=True)
    except Exception as e:
        print(f"[EMBEDDING CACHE] Warning: failed to load persistent cache: {e}", flush=True)

# ── Native vector engine (sqlite-vec or pgvector) ────────────────────────────
# Lazy-initialised on first retrieval call to allow DB to boot first.
_native_vec_engine = None
_native_vec_lock = threading.Lock()  # guards one-time lazy init of _native_vec_engine

def _get_native_vec_engine():
    """Lazy-initialises and returns the best available native vector engine.

    Double-checked lock pattern: the fast path (engine already set) runs without
    acquiring the lock; the slow path (first call) acquires it and re-checks so
    two concurrent first-callers never both run the potentially expensive init.
    """
    global _native_vec_engine
    if _native_vec_engine is None:
        with _native_vec_lock:
            if _native_vec_engine is None:  # re-check inside the lock
                try:
                    from src.db.database import engine_master
                    if engine_master is not None and engine_master.dialect.name == "postgresql":
                        _native_vec_engine = _init_pgvector(engine_master)
                    else:
                        _native_vec_engine = _init_sqlite_vec()
                except Exception as e:
                    print(f"[VEC SEARCH] Engine init failed ({e}); using Python cosine.", flush=True)
                    _native_vec_engine = "python"  # sentinel: use Python fallback
    return _native_vec_engine

def _init_sqlite_vec():
    """Initialises sqlite-vec shadow table next to the active SQLite file."""
    try:
        import sqlite_vec, sqlite3, struct
        from src.db.database import engine_master
        if engine_master is None:
            return "python"
        db_url = str(engine_master.url)
        db_path = db_url.replace("sqlite:///", "").replace("sqlite://", "")
        if not os.path.exists(db_path):
            return "python"
        # timeout=0: fail instantly on lock (no waiting), WAL mode for concurrent reads
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=0)
        conn.execute("PRAGMA journal_mode=WAL")  # WAL: multiple readers + 1 writer simultaneously
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS vec_chunks
            USING vec0(chunk_id INTEGER PRIMARY KEY, embedding FLOAT[768])
        """)
        conn.commit()
        conn.close()
        print(f"[VEC SEARCH] sqlite-vec native engine ready (db: {db_path}).", flush=True)
        return {"type": "sqlite-vec", "db_path": db_path}
    except ImportError:
        print("[VEC SEARCH] sqlite-vec not installed; using Python cosine.", flush=True)
        return "python"
    except Exception as e:
        print(f"[VEC SEARCH] sqlite-vec init failed ({e}); using Python cosine.", flush=True)
        return "python"

def _init_pgvector(pg_engine):
    """Initialises pgvector extension and HNSW index on PostgreSQL."""
    try:
        from sqlalchemy import text
        with pg_engine.begin() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS pg_vec_chunks (
                    chunk_id INTEGER PRIMARY KEY,
                    embedding vector(768)
                )"""))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_pg_vec_hnsw
                ON pg_vec_chunks USING hnsw (embedding vector_cosine_ops)
                WITH (m=16, ef_construction=64)"""))
        print("[VEC SEARCH] pgvector HNSW engine ready.", flush=True)
        return {"type": "pgvector", "engine": pg_engine}
    except Exception as e:
        print(f"[VEC SEARCH] pgvector init failed ({e}); using Python cosine.", flush=True)
        return "python"

def _flatten_embedding_vector(v):
    """Unwraps a vector nested in however many list-of-one-list layers get_embedding()
    left in place (observed varying by input length/backend response shape -- a single
    fixed-depth unwrap wasn't enough), down to a flat list of numbers."""
    while isinstance(v, list) and len(v) == 1 and isinstance(v[0], list):
        v = v[0]
    return v

def _vec_store_embedding(chunk_db_id, vector, engine):
    """Store a single embedding in the native vector engine."""
    if engine is None or engine == "python" or vector is None:
        return
    # Same defense as _vec_native_search() -- without it this silently fails (caught by
    # the bare except below) and native search finds nothing to search.
    vector = _flatten_embedding_vector(vector)
    try:
        if engine.get("type") == "sqlite-vec":
            import sqlite_vec, sqlite3, struct
            packed = struct.pack(f"{len(vector)}f", *vector)
            # timeout=0: if DB is locked by another user, skip instantly (no waiting)
            conn = sqlite3.connect(engine["db_path"], check_same_thread=False, timeout=0)
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
            conn.execute("INSERT OR REPLACE INTO vec_chunks(chunk_id, embedding) VALUES (?, ?)",
                         (chunk_db_id, packed))
            conn.commit()
            conn.close()
        elif engine.get("type") == "pgvector":
            from sqlalchemy import text
            vec_str = "[" + ",".join(str(v) for v in vector) + "]"
            with engine["engine"].begin() as conn:
                conn.execute(text("""
                    INSERT INTO pg_vec_chunks (chunk_id, embedding) VALUES (:cid, CAST(:emb AS vector))
                    ON CONFLICT (chunk_id) DO UPDATE SET embedding = EXCLUDED.embedding
                """), {"cid": chunk_db_id, "emb": vec_str})
    except Exception:
        pass  # Never crash audit on vector storage failure — next run will retry

def _vec_native_search(query_vector, filenames, top_k, engine, report_id=None):
    """Perform KNN search using native engine. Returns {chunk_db_id: similarity}."""
    if engine is None or engine == "python" or query_vector is None:
        return {}
    # An empty filenames list means "no evidence files for this control/session" --
    # both branches below used to treat that as "no filter" and search every chunk
    # in the entire document_chunks/pg_vec_chunks table, across every session and
    # every client sharing this deployment, silently handing the LLM someone else's
    # document content as "evidence" instead of correctly reporting no evidence
    # available. Must return no results here, before either SQL branch runs.
    if not filenames:
        return {}
    # get_embedding() can return a vector wrapped in list-of-one-list, and how many
    # layers varies (observed differing by input length) -- without unwrapping fully,
    # sqlite-vec's struct.pack blows up and pgvector's CAST(... AS vector) gets a
    # doubly-bracketed literal it can't parse ("invalid input syntax for type vector").
    query_vector = _flatten_embedding_vector(query_vector)
    try:
        if engine.get("type") == "sqlite-vec":
            import sqlite_vec, sqlite3, struct
            packed_q = struct.pack(f"{len(query_vector)}f", *query_vector)
            # timeout=0: if DB is locked, fail instantly — never wait — Python cosine takes over
            conn = sqlite3.connect(engine["db_path"], check_same_thread=False, timeout=0)
            conn.enable_load_extension(True)
            sqlite_vec.load(conn)
            conn.enable_load_extension(False)
            placeholders = ",".join(["?"]*len(filenames))
            report_clause = " AND dc.report_id = ? " if report_id is not None else " "
            sql = (f"SELECT vc.chunk_id, vc.distance FROM vec_chunks vc "
                   f"JOIN document_chunks dc ON dc.id=vc.chunk_id "
                   f"WHERE dc.filename IN ({placeholders}){report_clause}"
                   f"AND vc.embedding MATCH ? AND K=? ORDER BY vc.distance")
            sql_params = [*filenames] + ([report_id] if report_id is not None else []) + [packed_q, top_k*4]
            rows = conn.execute(sql, sql_params).fetchall()
            conn.close()
            return {r[0]: max(0.0, 1.0-(r[1]/2.0)) for r in rows}
        elif engine.get("type") == "pgvector":
            from sqlalchemy import text
            vec_str = "[" + ",".join(str(v) for v in query_vector) + "]"
            report_clause = "AND dc.report_id = :report_id " if report_id is not None else ""
            sql = text("SELECT pvc.chunk_id, 1-(pvc.embedding <=> CAST(:vec_str AS vector)) AS sim "
                       "FROM pg_vec_chunks pvc JOIN document_chunks dc ON dc.id=pvc.chunk_id "
                       f"WHERE dc.filename = ANY(:fn_list) {report_clause}ORDER BY sim DESC LIMIT :top_k_val")
            params = {"vec_str": vec_str, "fn_list": list(filenames), "top_k_val": top_k * 4}
            if report_id is not None:
                params["report_id"] = report_id
            with engine["engine"].begin() as conn:
                rows = conn.execute(sql, params).fetchall()
            return {r[0]: float(r[1]) for r in rows}
    except Exception as e:
        print(f"[VEC SEARCH] Native search error ({e}); falling back to Python cosine.", flush=True)
    return {}

# Cross-Encoder lazy-loading variables
_RERANKER_MODEL = None
_RERANKER_ACTIVE_MODE = None

def get_reranker(mode="quick"):
    """Lazy-loads and caches the selected Cross-Encoder model.
    Toggles loaded models dynamically to prevent excessive RAM usage.
    """
    global _RERANKER_MODEL, _RERANKER_ACTIVE_MODE

    if str(mode or "").strip().lower() in ("none", "off", "disabled", "false"):
        return None
    
    # Map friendly modes to Hugging Face models
    model_name = "cross-encoder/ms-marco-MiniLM-L-6-v2" if mode == "quick" else "BAAI/bge-reranker-base"
    
    if _RERANKER_MODEL is None or _RERANKER_ACTIVE_MODE != mode:
        # If another model is active, unload it first to protect RAM
        if _RERANKER_MODEL is not None:
            print(f"[RERANKER] Unloading active model '{_RERANKER_ACTIVE_MODE}' to free memory...", flush=True)
            _RERANKER_MODEL = None
            import gc
            gc.collect()
            
        try:
            from sentence_transformers import CrossEncoder
            print(f"[RERANKER] Loading model '{model_name}' (Mode: {mode.upper()}). First run will download file...", flush=True)
            _RERANKER_MODEL = CrossEncoder(model_name, max_length=512)
            _RERANKER_ACTIVE_MODE = mode
            print(f"[RERANKER] Model '{model_name}' loaded successfully.", flush=True)
        except Exception as e:
            print(f"[RERANKER ERROR] Failed to load CrossEncoder model '{model_name}': {e}", flush=True)
            
    return _RERANKER_MODEL

# Configurable defaults for retrieval
DEFAULT_TOP_K = {
    "pdf": 12,
    "docx": 12,
    "txt": 12,
    "xlsx": 12,
    "csv": 12,
    "pptx": 12,
    "image": 12
}

# Flavor-signal terms for the dual policy/evidence retrieval pass (see
# _retrieve_rag_context): a chunk heavy on either list scores well on that flavor's
# BM25 query even if it doesn't otherwise match the control's own keywords strongly --
# e.g. a dated log entry should surface for the evidence pass even on a control whose
# own keyword list is policy-document-flavored.
POLICY_SIGNAL_TERMS = [
    "policy", "procedure", "standard", "shall", "must", "should", "approved",
    "documented", "requirement", "guideline", "framework", "governance",
    "mandate", "revision", "version", "effective date", "review cycle",
    "document owner", "approved by", "document title", "policy status",
    "effective", "annual review", "sign-off", "approver", "implementation"
]
EVIDENCE_SIGNAL_TERMS = [
    "log", "report", "screenshot", "evidence", "completed", "executed",
    "performed", "record", "timestamp", "date", "confirmed", "verified",
    "output", "result", "export", "successful"
]



def load_top_k_config():
    config_path = os.path.join("config", "retrieval_config.json")
    config = dict(DEFAULT_TOP_K)
    
    if not os.path.exists(config_path):
        try:
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w") as cf:
                json.dump(DEFAULT_TOP_K, cf, indent=4)
        except Exception as e:
            print(f"[CONFIG ERROR] Failed to write default retrieval_config.json: {e}")
            
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as cf:
                file_config = json.load(cf)
                for k, v in file_config.items():
                    if k in config and isinstance(v, int):
                        config[k] = v
            print(f"[CONFIG] Loaded custom TOP_K overrides: {file_config}")
        except Exception as e:
            print(f"[CONFIG ERROR] Failed to load retrieval_config.json: {e}")
            
    return config

# Cache the config at module load time so _retrieve_rag_context() (called once
# per control, potentially 93x per full audit) doesn't re-read the file and
# re-print the override log on every single call.
_TOP_K_CONFIG_CACHE = None

def _get_top_k_config():
    """Returns the cached retrieval TOP_K config, loading it once on first call."""
    global _TOP_K_CONFIG_CACHE
    if _TOP_K_CONFIG_CACHE is None:
        _TOP_K_CONFIG_CACHE = load_top_k_config()
    return _TOP_K_CONFIG_CACHE


def save_document_chunks(filename, text, report_id=None):
    """Splits a document text into overlapping paragraph windows (> 40 chars), prepends parent section headers, and writes to ShaktiDB.

    report_id scopes the delete-before-insert to THIS session's own prior chunks
    for `filename` -- without it, two different sessions uploading a
    identically-named file (e.g. "ISO27001_Policy.pdf") would silently delete
    and overwrite each other's chunks, since filename alone was the only key.
    report_id=None falls back to the old filename-only scoping (only expected
    for call sites that couldn't resolve a report_id).
    """
    # ── HTML Pre-Pass: Strip raw HTML markup tags (script, style, head, divs) ──
    # Prevents 2.5MB raw HTML files (like NOCPL reports) from creating 80+ raw markup
    # chunks that consume all server RAM and trigger OOM python process exit.
    if text and (filename.lower().endswith((".html", ".htm")) or "<html" in text[:1000].lower() or "<body" in text[:1000].lower()):
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup(["script", "style", "head", "meta"]):
                tag.decompose()
            text = soup.get_text("\n")
        except Exception:
            text = re.sub(r'<[^>]+>', ' ', text)

    session = SessionLocal()
    try:
        with force_master():
            # Delete existing chunks for this file (scoped to this session
            # when report_id is known) to prevent duplicates on re-upload.
            _del_q = session.query(DocumentChunk).filter(DocumentChunk.filename == filename)
            if report_id is not None:
                _del_q = _del_q.filter(DocumentChunk.report_id == report_id)
            _del_q.delete()

            # Purge this filename's cached embeddings too. The cache is keyed by
            # (filename, chunk_index), not content -- if a file gets re-uploaded with
            # revised content under the same name, stale (filename, index) keys would
            # otherwise survive and get silently reused for the new chunk text, since
            # the embedding step only computes a fresh vector when the key is missing.
            stale_keys = [k for k in _chunk_embeddings_cache if k[0] == filename]
            if stale_keys:
                for k in stale_keys:
                    del _chunk_embeddings_cache[k]
                try:
                    with open(CACHE_FILE, "wb") as f:
                        pickle.dump(_chunk_embeddings_cache, f)
                except Exception as e:
                    print(f"[EMBEDDING CACHE] Warning: failed to persist cache after purge: {e}", flush=True)
                print(f"[EMBEDDING CACHE] Purged {len(stale_keys)} stale embedding(s) for re-uploaded file '{filename}'.", flush=True)

            cached_chunks = _ingested_chunks_cache.get(_cache_key(filename))
            if cached_chunks:
                chunks_saved = 0
                for idx, (p_content, metadata) in enumerate(cached_chunks):
                    # Split custom chunk content (Parent) into child sentences
                    sentences = []
                    raw_s = re.split(r'(?<=[.!?])\s+', p_content)
                    for s in raw_s:
                        s_strip = s.strip()
                        if len(s_strip.split()) >= 4:
                            sentences.append(s_strip)
                    if not sentences:
                        sentences = [p_content]
                        
                    for s_idx, sentence in enumerate(sentences):
                        child_metadata = dict(metadata)
                        child_metadata["parent_context"] = p_content
                        child_metadata["sentence_index"] = s_idx
                        
                        # Prepend context to the sentence vector to maintain scoping context
                        child_content = sentence
                        if metadata.get("section_heading"):
                            child_content = f"[{metadata['section_heading']}] {child_content}"
                        elif metadata.get("slide_title"):
                            child_content = f"[{metadata['slide_title']}] {child_content}"
                        elif metadata.get("sheet_name"):
                            child_content = f"[{metadata['sheet_name']}] {child_content}"
                            
                        chunk_id = hashlib.md5(f"{filename}_{idx}_{s_idx}_{child_content}".encode('utf-8')).hexdigest()[:8]
                        child_metadata["chunk_id"] = f"chunk_{chunk_id}"
                        
                        db_chunk = DocumentChunk(
                            filename=filename,
                            report_id=report_id,
                            chunk_index=chunks_saved,
                            content=child_content,
                            metadata_json=json.dumps(child_metadata),
                            source_file=child_metadata.get("source_file"),
                            source_type=child_metadata.get("source_type"),
                            chunk_id=child_metadata.get("chunk_id"),
                            # These previously only lived inside metadata_json (a JSON
                            # blob), never in their own typed columns, despite the
                            # columns existing on the model -- populating them enables
                            # direct DB filtering/joins by page/row/slide/image later.
                            page_number=child_metadata.get("page_number"),
                            row_number=child_metadata.get("start_row"),
                            slide_number=child_metadata.get("slide_number"),
                            image_id=child_metadata.get("image_id"),
                            section_heading=child_metadata.get("section_heading")
                        )
                        session.add(db_chunk)
                        chunks_saved += 1
                session.commit()
                print(f"[RAG] Successfully stored {chunks_saved} pointwise parent-child custom cached chunks for '{filename}' in database.")
                return

            # Fallback split into double newlines chunks (paragraphs)
            # Minimum 8 words (more reliable than 40 chars for ISO policy text)
            MAX_CHUNK_CHARS = 2000  # raised from 1200 to prevent silent truncation of document sections
            raw_paragraphs = [p.strip() for p in text.split('\n\n') if len(p.strip().split()) >= 8]
            
            # Prevent silent truncation: if any paragraph is longer than 800 characters,
            # split it by single newlines so it fits cleanly in sliding windows.
            paragraphs = []
            for rp in raw_paragraphs:
                if len(rp) > 800:
                    sub_paras = [sp.strip() for sp in rp.split('\n') if len(sp.strip().split()) >= 4]
                    paragraphs.extend(sub_paras)
                else:
                    paragraphs.append(rp)
            
            # Fallback to single newline paragraphs if double newline yields no results,
            # or if the split resulted in too few, very long blocks (often happens with pdfplumber text).
            if not paragraphs or len(paragraphs) <= 5 or (len(paragraphs) > 0 and sum(len(p) for p in paragraphs) / len(paragraphs) > 1200):
                lines = text.split('\n')
                paragraphs = []
                cur = []
                SECTION_START = _SECTION_START_RE
                for l in lines:
                    val = l.strip()
                    if not val:
                        continue
                    is_new = False
                    if cur:
                        if SECTION_START.match(val):
                            is_new = True
                        else:
                            last_line = cur[-1]
                            if last_line and last_line[-1] in ('.', '?', '!', '"', '”'):
                                if not last_line.endswith("i.e.") and not last_line.endswith("e.g.") and not last_line.endswith("approx."):
                                    if val[0].isupper() or val[0].isdigit():
                                        is_new = True
                    if is_new and cur:
                        paragraphs.append(" ".join(cur))
                        cur = []
                    cur.append(val)
                if cur:
                    paragraphs.append(" ".join(cur))
                paragraphs = [p for p in paragraphs if len(p.split()) >= 8]
                
            HEADER_REGEX = _HEADER_RE  # module-level constant, not re-compiled each call

            current_section = ""
            section_aware_paras = []
            for p in paragraphs:
                p_str = p.strip()
                match = HEADER_REGEX.match(p_str)
                if match and len(p_str) < 120:
                    current_section = p_str
                section_aware_paras.append((current_section, p_str))
                
            # Store sliding windows of 3 paragraphs, stride = 1
            window_size = 3
            stride = 1
            chunks_saved = 0
            for idx in range(0, len(section_aware_paras), stride):
                window_data = section_aware_paras[idx : idx + window_size]
                if not window_data:
                    break
                
                # Retrieve the most specific/recent section header for the window
                window_section = ""
                for sec, _ in window_data:
                    if sec:
                        window_section = sec
                        
                window_paras = [p for _, p in window_data]
                p_text = "\n\n".join(window_paras)
                # Keep raw parent context without section wrapper in metadata if we want it clean
                p_parent = p_text
                if window_section:
                    p_text = f"[{window_section}]\n{p_text}"
                # Hard cap: split oversized chunks (e.g. dense PDF pages) at sentence boundaries
                if len(p_text) > MAX_CHUNK_CHARS:
                    # Find the last sentence boundary before the cap
                    cut = p_text.rfind('.', 0, MAX_CHUNK_CHARS)
                    if cut == -1:
                        cut = MAX_CHUNK_CHARS
                    p_text = p_text[:cut + 1].strip()
                    p_parent = p_text

                # Split parent context into child sentences
                sentences = []
                raw_s = re.split(r'(?<=[.!?])\s+', p_text)
                for s in raw_s:
                    s_strip = s.strip()
                    if len(s_strip.split()) >= 4:
                        sentences.append(s_strip)
                if not sentences:
                    sentences = [p_text]

                for s_idx, sentence in enumerate(sentences):
                    _, ext = os.path.splitext(filename.lower())
                    SUPPORTED_TYPES_LOCAL = {
                        ".pdf": "pdf",   ".docx": "docx", ".doc": "docx",
                        ".txt": "txt",   ".xlsx": "xlsx",  ".xls": "xlsx",
                        ".csv": "csv",   ".pptx": "pptx",  ".ppt": "pptx",
                        ".html": "html", ".htm": "html",
                        ".png": "image", ".jpg": "image",   ".jpeg": "image"
                    }
                    src_type = SUPPORTED_TYPES_LOCAL.get(ext, ext.lstrip(".") if ext else "txt")
                    
                    child_metadata = {
                        "source_file": filename,
                        "source_type": src_type,
                        "section_heading": window_section,
                        "parent_context": p_parent,
                        "sentence_index": s_idx,
                        "chunk_id": f"chunk_fallback_{idx}_{s_idx}"
                    }
                    
                    child_content = sentence
                    # If the split sentence doesn't have the section prefix, add it to help vector retrieval
                    if window_section and not sentence.startswith('['):
                        child_content = f"[{window_section}] {sentence}"
                        
                    chunk = DocumentChunk(
                        filename=filename,
                        report_id=report_id,
                        chunk_index=chunks_saved,
                        content=child_content,
                        metadata_json=json.dumps(child_metadata),
                        source_file=child_metadata.get("source_file"),
                        source_type=child_metadata.get("source_type"),
                        chunk_id=child_metadata.get("chunk_id")
                    )
                    session.add(chunk)
                    chunks_saved += 1
                
            session.commit()
            print(f"[RAG] Successfully stored {chunks_saved} fallback overlapping chunks for '{filename}' in database.")
    except Exception as e:
        session.rollback()
        print(f"[RAG ERROR] Failed to save document chunks for '{filename}': {e}")
    finally:
        _ingested_chunks_cache.pop(_cache_key(filename), None)
        session.close()

def _get_ollama_embedding(text, model="nomic-embed-text", url=None):
    try:
        from src.core.llm_client import get_embedding
        return get_embedding(text, model=model)
    except Exception as e:
        print(f"[HYBRID RAG WARNING] Failed to get embedding for text: {e}")
    return None

def _cosine_similarity(v1, v2):
    if v1 is None or v2 is None:
        return 0.0
    # Defensively flatten list-of-one-list nesting if passed (see _flatten_embedding_vector)
    v1 = _flatten_embedding_vector(v1)
    v2 = _flatten_embedding_vector(v2)
    try:
        dot_product = sum(x * y for x, y in zip(v1, v2))
        norm_v1 = sum(x * x for x in v1) ** 0.5
        norm_v2 = sum(x * x for x in v2) ** 0.5
        if norm_v1 == 0 or norm_v2 == 0:
            return 0.0
        return dot_product / (norm_v1 * norm_v2)
    except Exception as e:
        print(f"[COSINE ERROR] Failed to compute similarity: {e}. v1_type={type(v1)}, v2_type={type(v2)}", flush=True)
        return 0.0

# Cache the fixed prompt template's own token cost -- measured once via the
# real tokenizer, not guessed. Only needs recomputing if the template text
# changes, which requires a process restart anyway, so a simple in-memory
# cache (not a TTL) is correct here.
_template_token_cache = {}


def _get_template_fixed_tokens(mode="standard"):
    """Real, measured token cost of a prompt template's fixed boilerplate
    (with {placeholder} markers stripped, since those are filled with real
    content at runtime and measured separately). Cached after first call."""
    if mode in _template_token_cache:
        return _template_token_cache[mode]
    try:
        from src.core.llm_client import count_tokens
        from src.ai.audit_chains import GENERATOR_PROMPT_TEMPLATE, EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE
        template = EXCEL_SCOPING_JUDGE_PROMPT_TEMPLATE if mode == "excel_scoping" else GENERATOR_PROMPT_TEMPLATE
        stripped = re.sub(r'\{[a-zA-Z_]+\}', '', template)
        tokens = count_tokens(stripped)
    except Exception as e:
        print(f"[TOKEN BUDGET] Failed to measure template cost, using safe fallback: {e}", flush=True)
        tokens = 4000  # conservative fallback -- larger than either real measured template
    _template_token_cache[mode] = tokens
    return tokens


def _calculate_dynamic_context_budget(controls_batch, mode="standard"):
    """
    Calculates the real evidence token budget for THIS specific control, instead
    of a fixed guess -- measures the actual fixed template cost (cached), the
    actual control fields for this call, and the actual accumulated knowledge-loop
    feedback for this control_id (which grows over time and was previously
    unaccounted for), then reserves worst-case completion room (4096, matching
    llm_client.py's real retry ceiling) plus a safety margin.

    Falls back to the previous fixed 3000/5000 defaults if anything fails, or if
    TARGET_CONTEXT_TOKENS/HARD_MAX_CONTEXT_TOKENS are explicitly set via env var
    (manual override always wins).
    """
    env_target = os.environ.get("TARGET_CONTEXT_TOKENS")
    env_hard_max = os.environ.get("HARD_MAX_CONTEXT_TOKENS")
    if env_target or env_hard_max:
        return (
            int(env_target) if env_target else 3000,
            int(env_hard_max) if env_hard_max else 5000,
        )

    FALLBACK_TARGET, FALLBACK_HARD_MAX = 3000, 5000
    CHAT_WRAPPER_TOKENS = 26          # measured: Gemma's <start_of_turn>... wrapper
    SAFETY_MARGIN_TOKENS = 300        # absorbs the chunk-selection char/4 estimate's imprecision
    # Floor for a starved slot. Not a target -- just enough for retrieval to
    # still select something so the audit runs and the warning below is seen,
    # rather than returning a negative budget and silently retrieving nothing.
    # audit_chains.py's trim backstop enforces the real slot size afterwards.
    MIN_USABLE_EVIDENCE_TOKENS = 512

    try:
        from src.core.llm_client import count_tokens, get_real_num_ctx
        num_ctx = get_real_num_ctx()  # real per-slot context via /props, matches audit_chains.py's get_num_ctx()
        COMPLETION_RESERVE_TOKENS = min(1536, max(768, int(num_ctx * 0.2)))  # dynamic completion reserve proportional to slot size

        template_tokens = _get_template_fixed_tokens(mode)

        ctrl = (controls_batch or [{}])[0]
        control_id = ctrl.get("control", "")
        fields_text = (
            f"{control_id}\n{ctrl.get('label','')}\n{ctrl.get('expected','')}\n{ctrl.get('prompt_hint','')}"
        )
        fields_tokens = count_tokens(fields_text)

        feedback_tokens = 0
        if control_id:
            try:
                from src.ai.knowledge_loop import get_auditor_feedback_few_shot
                code = control_id.split(" ")[0] if control_id else ""
                feedback_text = get_auditor_feedback_few_shot([code]) if code else ""
                feedback_tokens = count_tokens(feedback_text)
            except Exception as e:
                print(f"[TOKEN BUDGET] Failed to measure feedback size for '{control_id}': {e}", flush=True)

        overhead = (
            template_tokens + CHAT_WRAPPER_TOKENS + fields_tokens + feedback_tokens
            + COMPLETION_RESERVE_TOKENS + SAFETY_MARGIN_TOKENS
        )
        # The real evidence budget this slot can honour. This was previously
        # max(FALLBACK_HARD_MAX, num_ctx - overhead), which clamped UPWARD: on a
        # slot too small to hold the prompt at all, (num_ctx - overhead) came out
        # negative and the function still reported 5000. The caller then packed
        # 5000 tokens of evidence into a slot with no room for it, and
        # llama-server silently discarded the overflow -- evidence vanished with
        # no error and findings were decided on a fraction of the document.
        # Report the truth instead; a starved budget is a condition to surface,
        # not to paper over.
        hard_max = num_ctx - overhead
        if hard_max < MIN_USABLE_EVIDENCE_TOKENS:
            print(
                f"[TOKEN BUDGET] WARNING: slot context {num_ctx} leaves only {hard_max} token(s) "
                f"for evidence after {overhead} of overhead (minimum usable: {MIN_USABLE_EVIDENCE_TOKENS}). "
                f"Evidence WILL be trimmed and findings may be decided on partial documents. "
                f"Raise MIN_CTX_PER_REQUEST on the llama-server side.",
                flush=True
            )
            hard_max = MIN_USABLE_EVIDENCE_TOKENS
        target = int(hard_max * 0.7)

        print(
            f"[TOKEN BUDGET] control={control_id!r} template={template_tokens} fields={fields_tokens} "
            f"feedback={feedback_tokens} overhead_total={overhead} -> target={target} hard_max={hard_max}",
            flush=True
        )
        return target, hard_max
    except Exception as e:
        print(f"[TOKEN BUDGET] Dynamic calculation failed, using fallback {FALLBACK_TARGET}/{FALLBACK_HARD_MAX}: {e}", flush=True)
        return FALLBACK_TARGET, FALLBACK_HARD_MAX


def _retrieve_rag_context(
    context,
    controls_batch,
    file_names_list,
    llm_model,
    KEYWORD_SYNONYMS,
    audit_mode=None,
    report_id=None,
    policy_locked_filenames=None,
    evidence_locked_filenames=None,
    file_registry=None
):
    """Production RAG retrieval engine.
    Phase 3: Multi-document evidence aggregation — searches authorized uploaded files.
    Phase 4: Pipeline: keyword scoring -> exact dedup -> Jaccard near-dedup -> diversity -> rank.
    Phase 5: Token-budget accumulation -- dynamic per-control budget.
    Phase 8: Returns retrieved_chunk_metas for evidence source provenance.
    """
    # 0. Explicit Short-Circuit Guard for empty file authorization
    if not file_names_list:
        print("[RAG LOG] Empty file_names_list provided — returning empty context.", flush=True)
        return "", 0, []

    authorized_set = set(file_names_list or [])
    policy_set = set(policy_locked_filenames or [])
    evidence_set = set(evidence_locked_filenames or [])

    # Pre-compute scoping role for EVERY authorized file
    file_role_map = {}
    for fname in authorized_set:
        if fname in policy_set and fname in evidence_set:
            file_role_map[fname] = "DUAL_ROLE_CONFLICT"
            print(f"[ROLE CONFLICT WARNING] File '{fname}' listed in BOTH policy and evidence scoping lists.", flush=True)
        elif fname in policy_set:
            file_role_map[fname] = "POLICY"
        elif fname in evidence_set:
            file_role_map[fname] = "EVIDENCE"
        else:
            file_role_map[fname] = "SHARED_CONTEXT"

    TARGET_CONTEXT_TOKENS, HARD_MAX_CONTEXT_TOKENS = _calculate_dynamic_context_budget(controls_batch)

    # Deep mode (the default/thorough audit mode) gets more retrieval candidates and the
    # stronger reranker; Quick mode keeps the leaner original behavior. Anything other
    # than an explicit "Quick"-prefixed mode (including callers that don't pass audit_mode
    # at all, e.g. tests/run_evals.py's "Normal") is treated as Deep -- the more thorough
    # path is the safer default when the mode is unknown.
    is_quick_mode = str(audit_mode or "").strip().lower().startswith("quick")

    print(f"[RAG SMART CHUNK] Document text is {len(context)} chars. Scoped authorized files: {list(authorized_set)}.", flush=True)

    # 1. Ensure chunks exist for EACH authorized file individually, not just
    # "at least one exists". report_id scopes both the existence check and the
    # load below to THIS session's own chunks -- filename alone isn't a safe
    # key across sessions.
    #
    # This used to be a single aggregate count() over every authorized file: if
    # ANY of them already had chunks (e.g. a sibling file ingested for an
    # earlier control), the whole on-the-fly ingestion step was skipped -- so a
    # genuinely un-ingested file could silently never get chunks at all, for
    # the rest of the session.
    # force_master(): this file's ingestion writes (save_document_chunks, below
    # and in the on-the-fly branch) and this existence check must read the same
    # engine that just received them -- without it, this check (and the load
    # query further down) could route to a replica that hasn't caught up yet
    # via Postgres's own async streaming replication, see it as empty, and
    # trigger a redundant on-the-fly re-ingestion every single call.
    files_with_chunks = set()
    with force_master():
        session = SessionLocal()
        try:
            _existing_q = session.query(DocumentChunk.filename).filter(DocumentChunk.filename.in_(list(authorized_set)))
            if report_id is not None:
                _existing_q = _existing_q.filter(DocumentChunk.report_id == report_id)
            files_with_chunks = {row[0] for row in _existing_q.distinct().all()}
        except Exception as db_verify_err:
            print(f"[RAG WARNING] Failed to verify chunks count: {db_verify_err}")
        finally:
            session.close()

    missing_files = [f for f in authorized_set if f not in files_with_chunks]
    if missing_files:
        print(f"[RAG] No chunks found for {missing_files}. Ingesting on-the-fly...")
        if file_registry:
            # Per-file text is available -- ingest each missing file separately
            # so every resulting chunk keeps correct per-file attribution. This
            # used to save the FULL combined multi-file `context` string under
            # only file_names_list[0] in one call, so every chunk -- regardless
            # of which file it actually came from -- was tagged with that one
            # filename. That silently broke both the POLICY/EVIDENCE context
            # split above (every chunk looked like it came from whichever file
            # happened to be first) and the pre-existing evidence-source
            # provenance in chunk_metas, for any multi-file control that hit
            # this on-the-fly path (the common case for a fresh Excel-scoped
            # session, since chunks don't exist yet on the first control run).
            for fname in missing_files:
                per_file_text = file_registry.get(fname)
                if per_file_text:
                    try:
                        save_document_chunks(fname, per_file_text, report_id=report_id)
                    except Exception as ingest_err:
                        print(f"[RAG WARNING] Failed to ingest chunks for '{fname}': {ingest_err}")
                else:
                    print(f"[RAG WARNING] No text available in file_registry for '{fname}' -- skipping on-the-fly ingestion for this file.")
        else:
            # No per-file registry available (older/simpler callers, e.g. a
            # single-file context) -- fall back to the previous behavior.
            primary_file = file_names_list[0] if file_names_list else "default_document.pdf"
            try:
                save_document_chunks(primary_file, context, report_id=report_id)
            except Exception as ingest_err:
                print(f"[RAG WARNING] Failed to ingest chunks: {ingest_err}")

    # 2. Load ALL chunks from ALL uploaded files (this session's own only).
    # force_master(): this is the query that actually determines what gets
    # sent to the LLM. Without pinning to master, a read landing on a replica
    # that hasn't caught up with the ingestion write above sees zero chunks
    # and silently falls through to the raw-paragraph fallback below, which
    # tags every paragraph with file_names_list[0] regardless of which file it
    # actually came from -- defeating both the POLICY/EVIDENCE role split and
    # per-file evidence-source provenance, with no error or warning surfaced.
    with force_master():
        session = SessionLocal()
        db_chunks = []
        try:
            _load_q = session.query(DocumentChunk).filter(DocumentChunk.filename.in_(list(authorized_set)))
            if report_id is not None:
                _load_q = _load_q.filter(DocumentChunk.report_id == report_id)
            db_chunks = _load_q.all()
        except Exception as db_query_err:
            print(f"[RAG WARNING] Database query failed: {db_query_err}")
        finally:
            session.close()

    SUPPORTED_TYPES_LOCAL = {
        ".pdf": "pdf",   ".docx": "docx", ".doc": "docx",
        ".txt": "txt",   ".xlsx": "xlsx",  ".xls": "xlsx",
        ".csv": "csv",   ".pptx": "pptx",  ".ppt": "pptx",
        ".html": "html", ".htm": "html",
        ".png": "image", ".jpg": "image",   ".jpeg": "image"
    }
    type_counts = {}
    for fname in file_names_list:
        _, ext = os.path.splitext(fname.lower())
        ftype = SUPPORTED_TYPES_LOCAL.get(ext, "pdf")
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
    file_type = max(type_counts, key=type_counts.get) if type_counts else "pdf"

    top_k_config = _get_top_k_config()  # cached — reads disk once, not per control
    configured_top_k = top_k_config.get(file_type, 30)
    # Deep mode enforces the enterprise zero-leak floor of 30 (pdf/docx) or higher
    # if the config already specifies more (e.g. 35 for xlsx/csv). Quick mode keeps
    # whatever the config says — this only ever raises the floor, never lowers it.
    if not is_quick_mode:
        configured_top_k = max(configured_top_k, 30)


    # Fallback: paragraph split from raw context if DB empty
    paragraphs = []
    if not db_chunks:
        paragraphs = [p.strip() for p in context.split('\n\n') if p.strip()]
        if not paragraphs:
            paragraphs = [context]

    # Keyword synonyms expansion
    expanded_terms = set()
    for c in controls_batch:
        raw_words = set(re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c['control'].lower()))
        raw_words.update(re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c.get('label', '').lower()))
        for w in raw_words:
            expanded_terms.add(w)
            if w in KEYWORD_SYNONYMS:
                for syn in KEYWORD_SYNONYMS[w]:
                    expanded_terms.add(syn.lower())

    # Build weighted keyword dictionary
    batch_keywords = {}
    for c in controls_batch:
        c_keywords = c.get('keywords', {})
        if not c_keywords:
            c_keywords = {}
            for w in re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c['control'].lower()):
                c_keywords[w] = 2.0
            for w in re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', c.get('label', '').lower()):
                c_keywords[w] = 1.0
            for syn_w in list(c_keywords.keys()):
                if syn_w in KEYWORD_SYNONYMS:
                    for s in KEYWORD_SYNONYMS[syn_w]:
                        if s not in c_keywords:
                            c_keywords[s] = 1.5
        for kw, weight in c_keywords.items():
            batch_keywords[kw] = max(batch_keywords.get(kw, 0), weight)

    # Step 2: Score ALL chunks with real BM25 (IDF + document-length normalization,
    # replacing the previous plain term-count x weight scorer). Two flavored queries
    # (policy-leaning / evidence-leaning signal terms layered onto the same weighted
    # control keywords) are scored independently and merged by taking the max per
    # chunk, so a chunk strongly relevant to EITHER flavor surfaces -- not just chunks
    # that are generically on-topic for the control as a whole.
    def _weighted_query_tokens(extra_terms):
        tokens = []
        for kw, weight in batch_keywords.items():
            tokens.extend(kw.split() * max(1, round(weight)))
        for term in extra_terms:
            tokens.extend(term.split())
        return tokens

    policy_query_tokens = _weighted_query_tokens(POLICY_SIGNAL_TERMS)
    evidence_query_tokens = _weighted_query_tokens(EVIDENCE_SIGNAL_TERMS)

    chunk_texts = [c.content for c in db_chunks] if db_chunks else paragraphs
    tokenized_corpus = [re.findall(r'\b[a-zA-Z0-9_\-]{3,}\b', t.lower()) for t in chunk_texts]

    combined_scores = None
    if tokenized_corpus:
        try:
            from rank_bm25 import BM25Okapi
            bm25 = BM25Okapi(tokenized_corpus)
            policy_scores = bm25.get_scores(policy_query_tokens)
            evidence_scores = bm25.get_scores(evidence_query_tokens)
            # Cast off numpy scalars here so nothing downstream (JSON serialization,
            # DB float columns) has to know BM25 was ever involved.
            combined_scores = [float(max(p, e)) for p, e in zip(policy_scores, evidence_scores)]
        except Exception as bm25_err:
            print(f"[BM25 WARNING] BM25 scoring failed ({bm25_err}); falling back to term-count scorer.", flush=True)

        if combined_scores is None:
            # Fallback: original plain term-count x weight scorer.
            combined_scores = []
            for t in chunk_texts:
                t_lower = t.lower()
                score = 0
                combined_scores.append(score)

        # ── Governance Proof Chunk Reranking Boost ──────────────────────────
        # Prioritize chunks containing formal policy metadata (version, effective date,
        # approval, document owner) over generic educational definition paragraphs.
        GOVERNANCE_PROOF_TERMS = [
            "effective date", "version", "approved by", "document owner",
            "review cycle", "revision history", "effective", "annual review",
            "implementation", "status: active", "status: approved", "policy statement"
        ]
        DEFINITION_INTRO_TERMS = [
            "is defined as", "refers to", "what is ", "definition of",
            "background and introduction", "general overview", "purpose of this document is to define"
        ]

        if combined_scores and chunk_texts:
            boosted_scores = []
            for score, t in zip(combined_scores, chunk_texts):
                t_low = t.lower()
                gov_matches = sum(1 for term in GOVERNANCE_PROOF_TERMS if term in t_low)
                intro_matches = sum(1 for term in DEFINITION_INTRO_TERMS if term in t_low)
                
                score_mult = 1.0 + (gov_matches * 0.15) - (intro_matches * 0.10)
            combined_scores = boosted_scores

    scored_chunks = []
    if db_chunks:
        for score, chunk in zip(combined_scores or [], db_chunks):
            src_fname = chunk.filename
            if chunk.metadata_json:
                try:
                    meta = json.loads(chunk.metadata_json)
                    if "source_file" in meta:
                        src_fname = meta["source_file"]
                except Exception:
                    pass
            scored_chunks.append((score, chunk.content, chunk.chunk_index, src_fname, chunk))
    else:
        fallback_fname = file_names_list[0] if file_names_list else "default_document.pdf"
        for idx, (score, p) in enumerate(zip(combined_scores or [], paragraphs)):
            scored_chunks.append((score, p, idx, fallback_fname, None))

    unique_src_files = list({sc[3] for sc in scored_chunks})
    num_files = len(unique_src_files)


    # [HYBRID SEARCH] Compute Local Embeddings
    query_text = " ".join([f"{c['control']} {c['label']} {c.get('expected', '')}" for c in controls_batch])
    query_vector = _get_ollama_embedding(query_text)
    
    vector_similarities = {}
    if query_vector is not None:
        embeddings_store = _chunk_embeddings_cache
            
        chunks_to_embed = []
        for sc in scored_chunks:
            chunk_key = _embed_cache_key(sc[3], sc[2], sc[1])
            if chunk_key not in embeddings_store:
                chunks_to_embed.append((chunk_key, sc[1]))
                
        if chunks_to_embed:
            def embed_worker(item):
                key, content = item
                vector = _get_ollama_embedding(content)
                return key, vector
                
            from src.core.llm_client import get_llm_backend
            backend = os.environ.get("EMBEDDING_BACKEND", get_llm_backend()).lower()
            max_embed_workers = 2 if backend in ("llama.cpp", "llamacpp") else 4
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_embed_workers) as executor:
                embed_results = list(executor.map(embed_worker, chunks_to_embed))

            # Store in pickle cache AND native vector engine
            _native_engine = _get_native_vec_engine()
            for key, vector in embed_results:
                if vector is not None:
                    embeddings_store[key] = vector
            
            # Build chunk_db_id → key map to store in native engine
            # key = (filename, chunk_index, content_hash); we need the DB row id for sqlite-vec
            if _native_engine != "python" and _native_engine is not None:
                try:
                    session_tmp = SessionLocal()
                    for (fname, cidx, _content_hash), vector in zip(
                        [item[0] for item in chunks_to_embed],
                        [r[1] for r in embed_results]
                    ):
                        if vector is None:
                            continue
                        _row_q = session_tmp.query(DocumentChunk).filter(
                            DocumentChunk.filename == fname,
                            DocumentChunk.chunk_index == cidx
                        )
                        if report_id is not None:
                            _row_q = _row_q.filter(DocumentChunk.report_id == report_id)
                        row = _row_q.first()
                        if row:
                            _vec_store_embedding(row.id, vector, _native_engine)
                    session_tmp.close()
                except Exception as _vse:
                    pass  # Never crash audit on vec store failure
            
            try:
                with open(CACHE_FILE, "wb") as f:
                    pickle.dump(embeddings_store, f)
            except Exception as e:
                print(f"[EMBEDDING CACHE] Warning: failed to save persistent cache: {e}", flush=True)

        # ── Vector similarity: native engine first, Python cosine fallback ────
        _native_engine = _get_native_vec_engine()
        native_sims = _vec_native_search(query_vector, file_names_list, 40, _native_engine, report_id=report_id)

        if native_sims:
            # Map native chunk_db_id results back to (filename, chunk_index) keys
            try:
                session_tmp = SessionLocal()
                ids_to_fetch = list(native_sims.keys())
                rows = session_tmp.query(DocumentChunk).filter(
                    DocumentChunk.id.in_(ids_to_fetch)
                ).all()
                for row in rows:
                    chunk_key = (row.filename, row.chunk_index)
                    vector_similarities[chunk_key] = native_sims[row.id]
                session_tmp.close()
                print(f"[VEC SEARCH] Native {_native_engine.get('type','?')} returned {len(native_sims)} chunk similarities.", flush=True)
            except Exception as map_e:
                print(f"[VEC SEARCH] Native result mapping failed ({map_e}); using Python cosine.", flush=True)
                native_sims = {}

        if not native_sims:
            # Python cosine fallback (always accurate)
            for sc in scored_chunks:
                # embeddings_store (persistent, content-addressed) and
                # vector_similarities (this-call-only, keyed by filename+index like
                # the rest of this function) are two different dicts with two
                # different key conventions -- don't conflate them.
                embed_key = _embed_cache_key(sc[3], sc[2], sc[1])
                c_vec = embeddings_store.get(embed_key)
                if c_vec is not None:
                    sim = _cosine_similarity(query_vector, c_vec)
                    vector_similarities[(sc[3], sc[2])] = max(0.0, float(sim))

    # Merge Keyword & Vector Scores
    max_kw_score = max([sc[0] for sc in scored_chunks]) if scored_chunks else 0.0
    hybrid_scored_chunks = []
    for sc in scored_chunks:
        kw_score = sc[0]
        chunk_key = (sc[3], sc[2])
        vec_sim = vector_similarities.get(chunk_key, 0.0)
        
        norm_kw = (kw_score / max_kw_score) if max_kw_score > 0 else 0.0
        
        if query_vector is not None:
            hybrid_score = 0.4 * norm_kw + 0.6 * vec_sim
        else:
            hybrid_score = kw_score
            
        hybrid_scored_chunks.append((hybrid_score, sc[1], sc[2], sc[3], sc[4]))

    scored_chunks = hybrid_scored_chunks
    scored_chunks.sort(key=lambda x: x[0], reverse=True)
    matching_chunks = [c for c in scored_chunks if c[0] > 0.05]
    raw_retrieved = matching_chunks[:40] if matching_chunks else scored_chunks[:20]

    # Exact Duplicate Removal
    unique_raw = []
    seen_contents = set()
    for item in raw_retrieved:
        norm_content = item[1].strip()
        if norm_content not in seen_contents:
            seen_contents.add(norm_content)
            unique_raw.append(item)

    # Near-Duplicate Removal (Jaccard)
    def _jaccard(t1, t2):
        w1 = set(re.findall(r'\b\w+\b', t1.lower()))
        w2 = set(re.findall(r'\b\w+\b', t2.lower()))
        if not w1 and not w2:
            return 1.0
        return len(w1 & w2) / len(w1 | w2)

    SIMILARITY_THRESHOLD = 0.97
    deduplicated = []
    for item in unique_raw:
        is_dup = False
        for existing in deduplicated:
            if _jaccard(item[1], existing[1]) >= SIMILARITY_THRESHOLD:
                is_dup = True
                break
        if not is_dup:
            deduplicated.append(item)

    deduplicated.sort(key=lambda x: x[0], reverse=True)
    
    # ── Cross-Encoder Reranking ──────────────────────────────────────────────
    # An explicit RAG_RERANK_MODE env var always wins (operator override); otherwise
    # Deep mode defaults to the stronger BGE reranker and Quick mode keeps MiniLM.
    _env_rerank_mode = os.environ.get("RAG_RERANK_MODE")
    if _env_rerank_mode:
        rerank_mode = _env_rerank_mode.strip().lower()
    else:
        rerank_mode = "quick" if is_quick_mode else "deep"
    reranker = get_reranker(rerank_mode)
    
    if reranker is not None and deduplicated:
        # Use at least 40 raw candidates for the cross-encoder — evidence logs frequently
        # rank at positions 16-32 after hybrid scoring (policy text dominates early
        # positions). Giving the reranker the full 40-candidate window ensures no
        # evidence is invisible to the final relevance scoring pass. Widened to
        # configured_top_k when the config asks for more (e.g. 45 for xlsx/csv) so
        # every chunk that can actually reach the LLM gets properly reranked, not
        # just the first 40 of a larger kept set.
        rerank_window = max(40, configured_top_k)
        candidates = deduplicated[:rerank_window]
        try:
            pairs = [(query_text, item[1]) for item in candidates]
            rerank_scores = reranker.predict(pairs)

            reranked_candidates = []
            for i, item in enumerate(candidates):
                h_score = item[0]
                r_score = float(rerank_scores[i])
                final_score = 0.3 * h_score + 0.7 * r_score
                reranked_candidates.append((final_score, item[1], item[2], item[3], item[4]))

            reranked_candidates.sort(key=lambda x: x[0], reverse=True)
            # Only the untouched tail beyond the reranked window gets appended --
            # previously this re-added deduplicated[20:], which duplicated positions
            # 20-39 (already reranked above) back onto the list in their old,
            # un-reranked order.
            deduplicated = reranked_candidates + deduplicated[len(candidates):]
            print(f"[RERANK SUCCESS] Reranked {len(candidates)} candidate chunks using mode '{rerank_mode.upper()}'.", flush=True)
        except Exception as re_err:
            print(f"[RERANK WARNING] Reranking failed: {re_err}", flush=True)

    total_available_chunks = len(db_chunks) if db_chunks else len(paragraphs)

    # Evidence Diversity Enforcement
    # NOTE: only relevant when a control's search spans multiple files (Manual/AI
    # scoping) -- Excel-locked scoping restricts file_names_list to one file per
    # control upstream, so unique_src_files is never >1 there and this never fires.
    # DIVERSITY_MIN_SCORE gates which files are worth force-including: 0.05 was too
    # low (hybrid_score is roughly 0-1) and let near-zero-relevance chunks from
    # completely unrelated files get injected into every control's context, diluting
    # the limited token budget with noise. 0.15 still catches genuinely tangential
    # matches while dropping near-random ones.
    DIVERSITY_MIN_SCORE = 0.15
    unique_authorized_files = [f for f in unique_src_files if f in authorized_set]
    if len(unique_authorized_files) > 1 and deduplicated:
        top_window = deduplicated[:max(configured_top_k, 5)]
        files_in_top = {item[3] for item in top_window}
        missing_files = set(unique_authorized_files) - files_in_top
        for missing_fname in missing_files:
            if missing_fname not in authorized_set:
                continue  # STRICT GUARD: Never inject chunks from unauthorized files!
            best_for_file = None
            for candidate in scored_chunks:
                already_in = any(candidate[1].strip() == d[1].strip() for d in deduplicated)
                if candidate[3] == missing_fname and candidate[0] > DIVERSITY_MIN_SCORE and not already_in:
                    best_for_file = candidate
                    break
            if best_for_file:
                insert_at = min(configured_top_k, len(deduplicated))
                deduplicated.insert(insert_at, best_for_file)
                print(f"[RAG DIVERSITY] Injected chunk from authorized file '{missing_fname}' for multi-document evidence.", flush=True)

    deduplicated = deduplicated[:configured_top_k]

    # Token Budget Accumulation. No absolute relevance-score cutoff: the cross-encoder
    # reranker's scores are raw unbounded logits (commonly negative), not a 0-1 scale, so
    # a fixed threshold rejects almost everything regardless of actual relevance. The
    # reranker's ordering (already sorted best-first above) is what determines quality;
    # the token budget below is the real, meaningful stopping condition.
    #
    # Wrapped in a function so it can be run twice: once at the normal 3-5K budget, and
    # -- only if that yields nothing usable while real candidates existed beyond the
    # cutoff -- once more at an expanded budget, before falling back to a raw-text slice
    # (which is effectively a "give up" path that looks like NOT_FOUND downstream).
    def _select_and_condense(hard_max_tokens):
        selected_chunks = []
        current_tokens = 0
        for item in deduplicated:
            chunk_tokens = len(item[1]) // 4
            if current_tokens + chunk_tokens > hard_max_tokens:
                break
            selected_chunks.append(item)
            current_tokens += chunk_tokens
            if current_tokens >= TARGET_CONTEXT_TOKENS:
                break

        files_in_selected = list({item[3] for item in selected_chunks})
        print(
            f"[RAG LOG] file_type={file_type} | docs={len(file_names_list)} | "
            f"total_chunks={total_available_chunks} | selected={len(selected_chunks)} | "
            f"token_estimate={current_tokens} | budget={hard_max_tokens} | files_in_evidence={files_in_selected}"
        )

        # Chronological sort within each file
        file_order = {fname: idx for idx, fname in enumerate(file_names_list)}
        final_sorted = sorted(
            selected_chunks,
            key=lambda x: (file_order.get(x[3], 999), x[2])
        )

        # Collect chunk metadata with scoping_role & consistency assertion
        chunk_metas = []
        for _, content, index, src_file, chunk_obj in final_sorted:
            meta = {}
            if chunk_obj is not None and chunk_obj.metadata_json:
                try:
                    meta = json.loads(chunk_obj.metadata_json)
                except Exception:
                    meta = {"source_file": src_file}
            else:
                meta = {"source_file": src_file}

            if src_file not in file_role_map:
                print(f"[SCOPING CONSISTENCY ERROR] Authorized file '{src_file}' missing from file_role_map!", flush=True)
                scoping_role = "SHARED_CONTEXT"
            else:
                scoping_role = file_role_map[src_file]

            meta["scoping_role"] = scoping_role
            chunk_metas.append(meta)

        # Build condensed context (Parent-Child Sentence Window Expansion).
        #
        # When policy/evidence roles are distinguished (Excel Policy/Evidence
        # column scoping), assemble the context as explicitly separate, labeled
        # sections instead of one undifferentiated blob. scoping_role was already
        # computed per chunk above (file_role_map) and stored into chunk_metas,
        # but previously never used to structure the actual text the LLM reads --
        # the prompt asked the LLM to "evaluate POLICY and EVIDENCE separately"
        # from unlabeled raw paragraphs, i.e. re-derive the split itself instead
        # of being handed it. Standard (non-Excel-scoped) mode has no role
        # distinction to begin with (every file lands in SHARED_CONTEXT below),
        # so it's unaffected -- same flat concatenation, same order as before.
        has_role_split = bool(policy_set or evidence_set)
        policy_paragraphs, evidence_paragraphs, shared_paragraphs = [], [], []
        added_paragraphs = set()
        for _, child_content, _, src_file, chunk_obj in final_sorted:
            # Retrieve parent paragraph if available in metadata, else fallback to child sentence
            parent_context = child_content
            if chunk_obj is not None and chunk_obj.metadata_json:
                try:
                    meta = json.loads(chunk_obj.metadata_json)
                    if "parent_context" in meta:
                        parent_context = meta["parent_context"]
                except Exception:
                    pass

            paras = [para.strip() for para in parent_context.split('\n\n') if para.strip()]
            chunk_unique_text = []
            for para in paras:
                para_body = para
                if para.startswith('[') and ']' in para:
                    lines = para.split('\n', 1)
                    if len(lines) > 1:
                        para_body = lines[1]
                para_norm = " ".join(para_body.lower().split())
                if para_norm not in added_paragraphs:
                    chunk_unique_text.append(para)
                    added_paragraphs.add(para_norm)
            if not chunk_unique_text:
                continue

            block = "\n\n".join(chunk_unique_text) + "\n\n"
            role = file_role_map.get(src_file, "SHARED_CONTEXT")
            if role == "POLICY":
                policy_paragraphs.append(block)
            elif role == "EVIDENCE":
                evidence_paragraphs.append(block)
            else:
                shared_paragraphs.append(block)

        if has_role_split and (policy_paragraphs or evidence_paragraphs):
            condensed = ""
            if policy_paragraphs:
                condensed += "=== POLICY CONTEXT (what the requirement documents/mandates) ===\n\n" + "".join(policy_paragraphs)
            if evidence_paragraphs:
                condensed += "=== EVIDENCE CONTEXT (proof of actual implementation/operation) ===\n\n" + "".join(evidence_paragraphs)
            if shared_paragraphs:
                condensed += "=== ADDITIONAL CONTEXT ===\n\n" + "".join(shared_paragraphs)
        else:
            condensed = "".join(policy_paragraphs + evidence_paragraphs + shared_paragraphs)

        return condensed, len(selected_chunks), chunk_metas

    condensed_context, actual_top_k, retrieved_chunk_metas = _select_and_condense(HARD_MAX_CONTEXT_TOKENS)

    # Expanded-budget retry: only fires when the normal budget produced nothing at all
    # AND there were more candidates sitting beyond the cutoff that never got a chance --
    # i.e. the budget itself was the limiting factor, not a genuine absence of evidence.
    if not condensed_context.strip() and len(deduplicated) > actual_top_k:
        EXPANDED_CONTEXT_TOKENS = int(os.environ.get("EXPANDED_CONTEXT_TOKENS", "8000"))
        print(f"[RAG BUDGET] Normal budget ({HARD_MAX_CONTEXT_TOKENS} tokens) yielded no usable context "
              f"with {len(deduplicated)} candidates available -- retrying once at {EXPANDED_CONTEXT_TOKENS} tokens.", flush=True)
        condensed_context, actual_top_k, retrieved_chunk_metas = _select_and_condense(EXPANDED_CONTEXT_TOKENS)

    if not condensed_context.strip():
        condensed_context = context[:4000 if "3b" in llm_model.lower() else 6000]

    return condensed_context, actual_top_k, retrieved_chunk_metas
