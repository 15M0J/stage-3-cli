#!/usr/bin/env node

import { Command } from "commander";
import axios from "axios";
import fs from "fs";
import path from "path";
import os from "os";
import open from "open";
import chalk from "chalk";
import http from "http";
import crypto from "crypto";

const program = new Command();
const CONFIG_DIR = path.join(os.homedir(), ".insighta");
const CONFIG_FILE = path.join(CONFIG_DIR, "credentials.json");
const API_BASE_URL = process.env.INSIGHTA_API_URL || "http://localhost:3000";
const API_PREFIX = "/api/v1";

function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

function saveCredentials(data) {
  ensureConfigDir();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2));
}

function loadCredentials() {
  if (!fs.existsSync(CONFIG_FILE)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
}

function clearCredentials() {
  if (fs.existsSync(CONFIG_FILE)) {
    fs.unlinkSync(CONFIG_FILE);
  }
}

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "X-API-Version": "1"
  }
});

api.interceptors.request.use((config) => {
  const creds = loadCredentials();
  if (creds?.access_token) {
    config.headers.Authorization = `Bearer ${creds.access_token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest?._retry) {
      originalRequest._retry = true;
      const creds = loadCredentials();
      if (creds?.refresh_token) {
        try {
          const refreshResponse = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: creds.refresh_token
          });
          const refreshed = refreshResponse.data.data;
          const nextCreds = {
            ...creds,
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token
          };
          saveCredentials(nextCreds);
          originalRequest.headers.Authorization = `Bearer ${nextCreds.access_token}`;
          return api(originalRequest);
        } catch (refreshError) {
          clearCredentials();
          console.error(chalk.red("Session expired. Please login again."));
        }
      }
    }
    return Promise.reject(error);
  }
);

function base64UrlEncode(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}

function generateCodeChallenge(verifier) {
  return base64UrlEncode(crypto.createHash("sha256").update(verifier).digest());
}

program.name("insighta").description("Insighta Labs+ CLI Tool").version("1.0.0");

program
  .command("login")
  .description("Login with GitHub OAuth (PKCE)")
  .action(async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = crypto.randomBytes(16).toString("hex");
    const localPort = 3333;
    const redirectUri = `http://127.0.0.1:${localPort}/callback`;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, redirectUri);
      if (url.pathname !== "/callback") {
        res.statusCode = 404;
        res.end("Not found");
        return;
      }

      const code = url.searchParams.get("code");
      const returnedState = url.searchParams.get("state");

      if (returnedState !== state) {
        res.statusCode = 400;
        res.end("State mismatch.");
        server.close();
        return;
      }

      axios
        .post(`${API_BASE_URL}/auth/token`, {
          code,
          code_verifier: codeVerifier,
          redirect_uri: redirectUri,
          state
        })
        .then((response) => {
          saveCredentials(response.data.data);
          res.end("Login successful. Return to the CLI.");
          console.log(chalk.green(`\nLogged in as @${response.data.data.user.username}`));
        })
        .catch((error) => {
          const message = error.response?.data?.message || error.message;
          res.statusCode = 500;
          res.end("Authentication failed.");
          console.error(chalk.red("Auth failed:"), message);
          process.exitCode = 1;
        })
        .finally(() => {
          server.close();
        });
    });

    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(localPort, "127.0.0.1", resolve);
    });

    const loginUrl =
      `${API_BASE_URL}/auth/github?code_challenge=${encodeURIComponent(codeChallenge)}` +
      `&state=${encodeURIComponent(state)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}`;

    console.log(chalk.yellow("Opening browser for login..."));
    await open(loginUrl);
  });

program
  .command("logout")
  .description("Logout and clear credentials")
  .action(async () => {
    const creds = loadCredentials();
    if (creds?.refresh_token) {
      await api.post("/auth/logout", { refresh_token: creds.refresh_token }).catch(() => {});
    }
    clearCredentials();
    console.log(chalk.green("Logged out successfully."));
  });

program
  .command("whoami")
  .description("Show current user info")
  .action(() => {
    const creds = loadCredentials();
    if (!creds?.user) {
      console.log(chalk.red("Not logged in."));
      return;
    }
    console.log(chalk.cyan(`Logged in as @${creds.user.username} (${creds.user.role})`));
  });

const profiles = program.command("profiles").description("Manage profiles");

profiles
  .command("list")
  .description("List profiles with filters")
  .option("-g, --gender <gender>", "Filter by gender")
  .option("-c, --country <id>", "Filter by country ID")
  .option("--age-group <group>", "Filter by age group")
  .option("--min-age <number>", "Minimum age")
  .option("--max-age <number>", "Maximum age")
  .option("--sort-by <field>", "Sort field", "created_at")
  .option("--order <dir>", "Sort direction", "desc")
  .option("-p, --page <number>", "Page number", "1")
  .option("-l, --limit <number>", "Limit", "10")
  .action(async (options) => {
    try {
      const res = await api.get(`${API_PREFIX}/profiles`, { params: options });
      console.log(
        chalk.blue(
          `\nPage ${res.data.pagination.page} of ${res.data.pagination.total_pages} (${res.data.pagination.total_items} total)`
        )
      );
      console.table(
        res.data.data.map((profile) => ({
          ID: profile.id,
          Name: profile.name,
          Age: profile.age,
          Gender: profile.gender,
          Country: profile.country_name
        }))
      );
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("get <id>")
  .description("Get profile by ID")
  .action(async (id) => {
    try {
      const res = await api.get(`${API_PREFIX}/profiles/${id}`);
      console.log(chalk.cyan("\nProfile Details:"));
      console.log(JSON.stringify(res.data.data, null, 2));
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("search <query>")
  .description("Search profiles naturally")
  .option("-p, --page <number>", "Page number", "1")
  .option("-l, --limit <number>", "Limit", "10")
  .action(async (query, options) => {
    try {
      const res = await api.get(`${API_PREFIX}/profiles/search`, {
        params: { q: query, page: options.page, limit: options.limit }
      });
      console.log(chalk.blue(`\nFound ${res.data.pagination.total_items} results:`));
      console.table(
        res.data.data.map((profile) => ({
          Name: profile.name,
          Age: profile.age,
          Gender: profile.gender,
          Country: profile.country_name
        }))
      );
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("create")
  .description("Create a new profile")
  .requiredOption("-n, --name <name>", "Profile name")
  .option("--age <number>", "Age")
  .option("--gender <gender>", "Gender")
  .option("--country-id <code>", "Country code")
  .action(async (options) => {
    try {
      const res = await api.post(`${API_PREFIX}/profiles`, {
        name: options.name,
        age: options.age,
        gender: options.gender,
        country_id: options.countryId
      });
      console.log(chalk.green("Profile created successfully."));
      console.log(JSON.stringify(res.data.data, null, 2));
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("export")
  .description("Export profiles to CSV")
  .option("-g, --gender <gender>", "Filter by gender")
  .option("-c, --country <id>", "Filter by country ID")
  .action(async (options) => {
    try {
      const res = await api.get(`${API_PREFIX}/profiles/export`, {
        params: options,
        responseType: "arraybuffer"
      });
      const filename = `profiles_${Date.now()}.csv`;
      fs.writeFileSync(path.join(process.cwd(), filename), res.data);
      console.log(chalk.green(`Exported to ${filename}`));
    } catch (error) {
      console.error(chalk.red("Export failed:"), error.response?.data?.message || error.message);
    }
  });

program.parse();
