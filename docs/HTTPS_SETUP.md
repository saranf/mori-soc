# MORI HTTPS 설정 (Let's Encrypt) + 서버 실행

`https://mori.rmstudio.co.kr` 로 MORI 를 열어 GitHub Actions 가 **인증서 검증된 채로** 결과를
push 하게 한다. (직전 실패 `unknown url type` 은 시크릿에 스킴이 없어서였음 — 여기서 함께 해결.)

## 0. 상황 — 포트 충돌 주의

이 서버는 **호스트 80·443 을 이미 `lawtoyou_nginx_1`(다른 프로젝트 nginx) 이 점유**한다
(`docker ps` 확인). 그래서 **새 프록시로 80/443 을 다시 잡으면 충돌**한다. 정답은 **이미 443 을
쥔 그 nginx 에 `mori.rmstudio.co.kr` 가상호스트(server_name)를 얹어** MORI(:18000)로 프록시하는 것.
같은 포트를 **SNI(도메인)로 분기**하므로 충돌이 없다.

---

## 1. MORI 최신 배포 (먼저)

```bash
cd /backup/rmstudio/mori
git pull                     # 최신(개인정보 흐름/PDF/스킴보정 포함)
docker compose up -d --build mori-api mori-worker
docker compose ps            # mori-api healthy 확인
curl -s http://127.0.0.1:18000/health   # {"status":"ok"} 류
```

`.env` 에 공개 URL 을 https 로(선택이지만 권장 — UI 안내·복사 URL 이 정확해짐):

```bash
echo 'MORI_PUBLIC_URL=https://mori.rmstudio.co.kr' >> .env
docker compose up -d mori-api
```

---

## 2. Let's Encrypt 인증서 발급 (certbot · webroot)

80 은 `lawtoyou_nginx_1` 이 서빙 중이므로 **standalone 불가 → webroot** 로 발급한다.

```bash
# (a) ACME 챌린지용 웹루트 준비
sudo mkdir -p /var/www/certbot

# (b) 443 nginx(lawtoyou_nginx_1)가 이 경로의 챌린지를 서빙하도록,
#     config/nginx/mori.rmstudio.co.kr.conf 의 80 블록을 그 nginx 의 conf.d 에 먼저 넣는다.
#     그 nginx 의 conf 마운트 위치 찾기:
docker inspect lawtoyou_nginx_1 --format '{{json .Mounts}}' | tr ',' '\n' | grep -i conf
#   → 예: /path/lawtoyou/nginx/conf.d 를 컨테이너 /etc/nginx/conf.d 로 마운트
sudo cp config/nginx/mori.rmstudio.co.kr.conf <그_conf.d_경로>/
#     이 컨테이너가 /var/www/certbot 를 못 보면, 챌린지 location 의 root 를 그 컨테이너가
#     접근 가능한 경로로 맞추거나 아래 (d) DNS 방식을 쓴다.
docker exec lawtoyou_nginx_1 nginx -t && docker exec lawtoyou_nginx_1 nginx -s reload

# (c) certbot 로 발급 (호스트에 certbot 설치돼 있어야: apt install certbot)
sudo certbot certonly --webroot -w /var/www/certbot \
  -d mori.rmstudio.co.kr --agree-tos -m admin@rmstudio.co.kr --no-eff-email
#   → /etc/letsencrypt/live/mori.rmstudio.co.kr/ 에 fullchain.pem·privkey.pem 생성
```

> **(d) 웹루트가 번거로우면 DNS-01**: `sudo certbot certonly --manual --preferred-challenges dns
> -d mori.rmstudio.co.kr` 로 DNS TXT 레코드 한 번 추가해 발급(80 불필요). 갱신 시 재입력 필요하므로
> 가능하면 webroot 를 권장.

---

## 3. 443 프록시 활성화

`config/nginx/mori.rmstudio.co.kr.conf` 는 80·443 블록을 모두 담고 있다. 인증서가 생겼으니
그 nginx 에 (이미 2-b 에서 넣었다면) reload 만:

```bash
docker exec lawtoyou_nginx_1 nginx -t && docker exec lawtoyou_nginx_1 nginx -s reload
```

- **프록시 대상 주의**: 그 nginx 는 컨테이너다. `proxy_pass http://127.0.0.1:18000` 은 컨테이너
  자신을 가리키므로, **`http://172.17.0.1:18000`(docker0 게이트웨이)** 로 바꾼다(파일 주석 참고).
  인증서 파일도 그 컨테이너 안에서 보이도록 `/etc/letsencrypt` 볼륨 마운트가 있어야 한다
  (없으면 lawtoyou compose 에 `- /etc/letsencrypt:/etc/letsencrypt:ro` 추가 후 재기동).

확인:

```bash
curl -sSI https://mori.rmstudio.co.kr/health   # 200 + 유효 인증서
```

---

## 4. GitHub 레포 시크릿 — https 로 (직전 실패 해결)

레포 Settings → Secrets → Actions:

- `MORI_INGEST_URL = https://mori.rmstudio.co.kr`  ← **스킴 포함!** (이게 직전 push 실패 원인)
- (유료 Claude 경로면) `ANTHROPIC_API_KEY = <크레딧 있는 키>`

그리고 대상 레포에 **최신 워크플로/스크립트 재복사**(MORI UI 고급 팝업) 후 재스캔.

---

## 5. 자동 갱신

certbot 은 보통 `certbot.timer` 로 자동 갱신된다. 갱신 후 nginx reload 훅:

```bash
sudo certbot renew --dry-run
# 갱신 훅: /etc/letsencrypt/renewal-hooks/deploy/ 에 reload 스크립트 배치
echo 'docker exec lawtoyou_nginx_1 nginx -s reload' | sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

---

## 부록 — 80/443 이 비어있는 서버라면 (Caddy 자동 HTTPS)

다른 서버(80/443 미사용)에서는 `config/caddy/Caddyfile` + 아래 compose 서비스로 **인증서 자동**:

```yaml
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports: ["80:80", "443:443", "443:443/udp"]
    environment:
      PUBLIC_DOMAIN: ${PUBLIC_DOMAIN:-mori.rmstudio.co.kr}
      ACME_EMAIL: ${ACME_EMAIL:-admin@rmstudio.co.kr}
    volumes:
      - ./config/caddy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    networks: [soc]
    depends_on: [mori-api]
```

이 서버는 80/443 이 점유돼 **적용 불가** — §1~4 의 nginx vhost 방식을 쓴다.
