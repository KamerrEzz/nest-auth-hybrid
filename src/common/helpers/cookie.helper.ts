import type { Response } from 'express';
import { randomUUID } from 'crypto';

export class CookieHelper {
  /**
   * Establece las cookies de autenticación (sessionId y csrfToken)
   * @param res - Express Response object
   * @param sessionId - ID de la sesión
   * @param isProd - Si está en producción
   * @param maxAge - Tiempo de vida de las cookies en milisegundos
   * @returns El token CSRF generado
   */
  static setAuthCookies(
    res: Response,
    sessionId: string,
    isProd: boolean,
    maxAge: number,
  ): string {
    res.cookie('sessionId', sessionId, {
      httpOnly: true,
      secure: isProd,
      sameSite: 'strict',
      maxAge,
    });

    const csrfToken = randomUUID();
    res.cookie('csrfToken', csrfToken, {
      httpOnly: false,
      secure: isProd,
      sameSite: 'strict',
      maxAge,
    });

    return csrfToken;
  }

  /**
   * Limpia las cookies de autenticación
   * @param res - Express Response object
   */
  static clearAuthCookies(res: Response): void {
    res.clearCookie('sessionId');
    res.clearCookie('csrfToken');
  }
}
