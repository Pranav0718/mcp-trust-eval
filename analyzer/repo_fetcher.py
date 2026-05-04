import os
import requests
import base64


GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}


def parse_github_url(url: str) -> tuple:
    url = url.rstrip("/").replace("https://github.com/", "")
    parts = url.split("/")
    return parts[0], parts[1]


def get_repo_metadata(owner: str, repo: str) -> dict:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = requests.get(url, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    return {
        "full_name": data.get("full_name"),
        "description": data.get("description"),
        "owner_type": data.get("owner", {}).get("type"),
        "stars": data.get("stargazers_count", 0),
        "forks": data.get("forks_count", 0),
        "open_issues": data.get("open_issues_count", 0),
        "last_pushed": data.get("pushed_at"),
        "created_at": data.get("created_at"),
        "has_security_policy": False,
        "language": data.get("language"),
        "license": data.get("license", {}).get("name") if data.get("license") else None,
        "archived": data.get("archived", False),
        "default_branch": data.get("default_branch", "main"),
    }


def check_security_policy(owner: str, repo: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/SECURITY.md"
    resp = requests.get(url, headers=HEADERS, timeout=10)
    return resp.status_code == 200


def get_repo_tree(owner: str, repo: str, branch: str = "main") -> list:
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    resp = requests.get(url, headers=HEADERS, timeout=15)
    if resp.status_code != 200:
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1"
        resp = requests.get(url, headers=HEADERS, timeout=15)
    resp.raise_for_status()
    return resp.json().get("tree", [])


def get_file_content(owner: str, repo: str, path: str) -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=HEADERS, timeout=15)
    if resp.status_code != 200:
        return ""
    data = resp.json()
    if data.get("encoding") == "base64":
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return ""


def fetch_repo_files(owner: str, repo: str, metadata: dict) -> dict:
    RELEVANT_EXTENSIONS = {
        ".py", ".js", ".ts", ".json", ".yaml", ".yml",
        ".toml", ".txt", ".md", ".env", ".cfg", ".ini"
    }
    MAX_FILES = 60
    MAX_FILE_SIZE = 100000

    tree = get_repo_tree(owner, repo, metadata["default_branch"])
    files = {}
    count = 0

    for item in tree:
        if item["type"] != "blob":
            continue
        path = item["path"]
        ext = os.path.splitext(path)[1].lower()
        if ext not in RELEVANT_EXTENSIONS:
            continue
        if item.get("size", 0) > MAX_FILE_SIZE:
            continue
        if count >= MAX_FILES:
            break
        content = get_file_content(owner, repo, path)
        if content:
            files[path] = content
            count += 1

    return files


def fetch_repo(github_url: str) -> dict:
    owner, repo = parse_github_url(github_url)
    metadata = get_repo_metadata(owner, repo)
    metadata["has_security_policy"] = check_security_policy(owner, repo)
    files = fetch_repo_files(owner, repo, metadata)
    return {
        "owner": owner,
        "repo": repo,
        "metadata": metadata,
        "files": files
    }
