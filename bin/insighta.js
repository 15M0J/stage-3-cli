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
const API_BASE_URL = "http://localhost:3000";

// Helper: Ensure config directory exists
function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

// Helper: Save credentials
function saveCredentials(data) {
  ensureConfigDir();
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2));
}

// Helper: Load credentials
function loadCredentials() {
  if (!fs.existsSync(CONFIG_FILE)) return null;
  return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
}

// Helper: Axios instance with auth and version headers
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "X-API-Version": "1"
  }
});

api.interceptors.request.use(async (config) => {
  let creds = loadCredentials();
  if (creds && creds.access_token) {
    config.headers.Authorization = `Bearer ${creds.access_token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      let creds = loadCredentials();
      if (creds && creds.refresh_token) {
        try {
          const res = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: creds.refresh_token
          });
          const newCreds = {
            access_token: res.data.access_token,
            refresh_token: res.data.refresh_token,
            user: creds.user
          };
          saveCredentials(newCreds);
          originalRequest.headers.Authorization = `Bearer ${newCreds.access_token}`;
          return api(originalRequest);
        } catch (refreshError) {
          console.error(chalk.red("Session expired. Please login again."));
          fs.unlinkSync(CONFIG_FILE);
        }
      }
    }
    return Promise.reject(error);
  }
);

// PKCE Helpers
function base64UrlEncode(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function generateCodeVerifier() {
  return base64UrlEncode(crypto.randomBytes(32));
}
function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return base64UrlEncode(hash);
}

program
  .name("insighta")
  .description("Insighta Labs+ CLI Tool")
  .version("1.0.0");

// --- Auth Commands ---

program
  .command("login")
  .description("Login with GitHub OAuth (PKCE)")
  .action(async () => {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const state = crypto.randomBytes(16).toString('hex');
    const localPort = 3333;

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://localhost:${localPort}`);
      if (url.pathname === '/callback') {
        const code = url.searchParams.get('code');
        const returnedState = url.searchParams.get('state');

        if (returnedState !== state) {
          res.end("State mismatch.");
          return;
        }

        try {
          const response = await axios.post(`${API_BASE_URL}/auth/token`, {
            code,
            code_verifier: codeVerifier,
            redirect_uri: `http://localhost:3000/auth/github/callback`
          });

          saveCredentials(response.data.data);
          res.end("Login successful! Return to CLI.");
          console.log(chalk.green(`\nLogged in as @${response.data.data.user.username}`));
          process.exit(0);
        } catch (error) {
          console.error(chalk.red("Auth failed:"), error.response?.data?.message || error.message);
          res.end("Auth failed.");
          process.exit(1);
        }
      }
    }).listen(localPort);

    const loginUrl = `${API_BASE_URL}/auth/github?code_challenge=${codeChallenge}&state=${state}`;
    console.log(chalk.yellow("Opening browser for login..."));
    await open(loginUrl);
  });

program
  .command("logout")
  .description("Logout and clear credentials")
  .action(async () => {
    let creds = loadCredentials();
    if (creds) {
      await api.post("/auth/logout", { refresh_token: creds.refresh_token }).catch(() => {});
      fs.unlinkSync(CONFIG_FILE);
    }
    console.log(chalk.green("Logged out successfully."));
  });

program
  .command("whoami")
  .description("Show current user info")
  .action(() => {
    let creds = loadCredentials();
    if (!creds) return console.log(chalk.red("Not logged in."));
    console.log(chalk.cyan(`Logged in as @${creds.user.username} (${creds.user.role})`));
  });

// --- Profile Commands ---

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
      const res = await api.get("/api/profiles", { params: options });
      console.log(chalk.blue(`\nPage ${res.data.page} of ${res.data.total_pages} (${res.data.total} total)`));
      console.table(res.data.data.map(p => ({
        ID: p.id,
        Name: p.name,
        Age: p.age,
        Gender: p.gender,
        Country: p.country_name
      })));
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("get <id>")
  .description("Get profile by ID")
  .action(async (id) => {
    try {
      const res = await api.get(`/api/profiles/${id}`);
      console.log(chalk.cyan("\nProfile Details:"));
      console.log(JSON.stringify(res.data.data, null, 2));
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("search <query>")
  .description("Search profiles naturally")
  .action(async (query) => {
    try {
      const res = await api.get("/api/profiles/search", { params: { q: query } });
      console.log(chalk.blue(`\nFound ${res.data.total} results:`));
      console.table(res.data.data.map(p => ({
        Name: p.name,
        Age: p.age,
        Gender: p.gender,
        Country: p.country_name
      })));
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("create")
  .description("Create a new profile")
  .option("-n, --name <name>", "Profile name")
  .action(async (options) => {
    try {
      const res = await api.post("/api/profiles", { name: options.name });
      console.log(chalk.green("Profile created successfully!"));
      console.log(res.data.data);
    } catch (error) {
      console.error(chalk.red("Error:"), error.response?.data?.message || error.message);
    }
  });

profiles
  .command("export")
  .description("Export profiles to CSV")
  .option("--format <format>", "Export format", "csv")
  .option("-g, --gender <gender>", "Filter by gender")
  .option("-c, --country <id>", "Filter by country ID")
  .action(async (options) => {
    try {
      const res = await api.get("/api/profiles/export", { 
        params: options,
        responseType: 'arraybuffer'
      });
      const filename = `profiles_${Date.now()}.csv`;
      fs.writeFileSync(path.join(process.cwd(), filename), res.data);
      console.log(chalk.green(`Exported to ${filename}`));
    } catch (error) {
      console.error(chalk.red("Export failed:"), error.message);
    }
  });

program.parse();
