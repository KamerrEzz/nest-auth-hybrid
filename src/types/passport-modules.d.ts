declare module 'passport-local' {
  export class Strategy {
    constructor(options?: { usernameField?: string; passwordField?: string });
  }
}

declare module 'passport-jwt' {
  export class Strategy {
    constructor(options: {
      jwtFromRequest: (req: any) => string | null;
      ignoreExpiration?: boolean;
      secretOrKey: string;
    });
  }
  export const ExtractJwt: {
    fromAuthHeaderAsBearerToken: () => (req: any) => string | null;
  };
}

declare module 'passport-google-oauth20' {
  export class Strategy {
    constructor(options: {
      clientID: string;
      clientSecret: string;
      callbackURL: string;
      scope?: string[];
    });
  }
}

declare module 'passport-discord' {
  export class Strategy {
    constructor(options: {
      clientID: string;
      clientSecret: string;
      callbackURL: string;
      scope?: string[];
    });
  }
}

declare module 'passport-custom' {
  export class Strategy {
    constructor();
  }
}
