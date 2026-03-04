declare module "@saurbit/oauth2-server" {
  interface UserCredentials {
    username: string;
    level?: number;
  }
  interface AppCredentials {
    name: string;
  }
}

export {};
