---
name: nobrainer-reddit
description: Reddit CLI skill for Claude Code. Read posts, search subreddits, post comments, and manage your Reddit account from the terminal using PRAW (Python Reddit API Wrapper) with OAuth2 authentication. Personal use, non-commercial.
---

# NoBrainer Reddit CLI

Reddit interface for Claude Code — read, search, post, and monitor Reddit from your terminal.

## Setup

### 1. Install PRAW

```bash
pip3 install praw
```

### 2. Reddit API credentials

Register your app at: https://www.reddit.com/prefs/apps
Choose type: **script**

Store credentials in `~/.reddit_credentials.json`:
```json
{
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "username": "YOUR_REDDIT_USERNAME",
  "password": "YOUR_REDDIT_PASSWORD",
  "user_agent": "nobrainer-reddit-cli/1.0 by YOUR_USERNAME"
}
```

### 3. Initialize

```python
import praw, json
creds = json.load(open(os.path.expanduser("~/.reddit_credentials.json")))
reddit = praw.Reddit(**creds)
print(reddit.user.me())  # verify login
```

---

## Commands

### Read — hot posts from a subreddit

```python
import praw, json, os

creds = json.load(open(os.path.expanduser("~/.reddit_credentials.json")))
reddit = praw.Reddit(**creds)

for post in reddit.subreddit("python").hot(limit=10):
    print(f"[{post.score}] {post.title}")
    print(f"  {post.url}\n")
```

### Search — find posts by keyword

```python
for post in reddit.subreddit("all").search("claude code", limit=10, sort="new"):
    print(f"[r/{post.subreddit}] {post.title}")
    print(f"  {post.url}\n")
```

### Read comments on a post

```python
submission = reddit.submission(url="https://www.reddit.com/r/python/comments/...")
submission.comments.replace_more(limit=0)
for comment in submission.comments.list()[:20]:
    print(f"[{comment.score}] {comment.body[:200]}\n")
```

### Post — submit a text post

```python
subreddit = reddit.subreddit("test")
post = subreddit.submit(
    title="Test post from nobrainer-reddit-cli",
    selftext="This is the body of the post."
)
print(f"Posted: {post.url}")
```

### Comment on a post

```python
submission = reddit.submission(url="POST_URL")
comment = submission.reply("This is my comment.")
print(f"Commented: {comment.permalink}")
```

### My profile — recent activity

```python
me = reddit.user.me()
print(f"u/{me.name} | karma: {me.link_karma} post / {me.comment_karma} comment")

print("\n--- Recent posts ---")
for post in me.submissions.new(limit=5):
    print(f"[r/{post.subreddit}] {post.title}")

print("\n--- Recent comments ---")
for comment in me.comments.new(limit=5):
    print(f"[r/{comment.subreddit}] {comment.body[:100]}")
```

### Monitor subreddit — new posts stream

```python
print("Monitoring r/python for new posts... (Ctrl+C to stop)")
for post in reddit.subreddit("python").stream.submissions():
    print(f"[NEW] {post.title}")
    print(f"  {post.url}\n")
```

---

## Rate limits

- Free tier: **60 requests/minute**
- PRAW handles rate limiting automatically
- Check remaining: `reddit.auth.limits`

---

## Notes

- Credentials file should have `chmod 600 ~/.reddit_credentials.json`
- `user_agent` must be descriptive and unique per Reddit's API rules
- Script type OAuth only accesses your own account — no other users' private data
