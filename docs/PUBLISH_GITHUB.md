# Đưa source code lên GitHub

## Cách 1: GitHub CLI

Cài và đăng nhập GitHub CLI, sau đó chạy tại thư mục dự án:

```bash
git init
git add .
git commit -m "Initial CDIO4 AI SSH honeypot MVP"
gh repo create ai-ssh-honeypot-cdio4 --public --source=. --remote=origin --push
```

Đổi `--public` thành `--private` nếu nhóm chưa muốn công khai.

## Cách 2: Tạo repository trên website

1. Tạo repository rỗng, không thêm README hoặc .gitignore.
2. Sao chép URL HTTPS của repository.
3. Chạy:

```bash
git init
git add .
git commit -m "Initial CDIO4 AI SSH honeypot MVP"
git branch -M main
git remote add origin https://github.com/USERNAME/REPOSITORY.git
git push -u origin main
```

Không commit file `.env`, database trong `data/` hoặc SSH host key. Các tệp này đã được chặn trong `.gitignore`.
