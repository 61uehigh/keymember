/**
 * ### LoginFixture
 *
 * A synthetic page reproducing a login pattern common on Korean and global sites, with the
 * fields detection must find. Markup is written for these tests, not copied from any site.
 */
export interface LoginFixture {
  /**
   * ### name
   *
   * What the fixture represents.
   */
  readonly name: string;

  /**
   * ### html
   *
   * Body markup.
   */
  readonly html: string;

  /**
   * ### focus
   *
   * Selector of the input the user focuses.
   */
  readonly focus: string;

  /**
   * ### expected
   *
   * Expected detection: selectors of the found fields, the focused kind, and whether it is a signup form.
   */
  readonly expected: {
    readonly kind: "username" | "password" | "otp" | undefined;
    readonly username?: string;
    readonly password?: string;
    readonly otp?: string;
    readonly isSignup: boolean;
  };
}

export const LOGIN_FIXTURES: ReadonlyArray<LoginFixture> = [
  {
    name: "portal login with Korean labels and no autocomplete (아이디/비밀번호)",
    html: `
      <form action="/login">
        <label for="uid">아이디</label><input id="uid" name="uid" type="text">
        <label for="upw">비밀번호</label><input id="upw" name="upw" type="password">
        <button type="submit">로그인</button>
      </form>`,
    focus: "#uid",
    expected: {
      kind: "username",
      username: "#uid",
      password: "#upw",
      isSignup: false,
    },
  },
  {
    name: "email login with autocomplete tokens",
    html: `
      <form>
        <input id="e" type="email" autocomplete="username">
        <input id="p" type="password" autocomplete="current-password">
      </form>`,
    focus: "#p",
    expected: {
      kind: "password",
      username: "#e",
      password: "#p",
      isSignup: false,
    },
  },
  {
    name: "header search box before the login form must not become the user name",
    html: `
      <div role="search"><input id="q" name="q" placeholder="검색어를 입력하세요"></div>
      <form>
        <input id="login-id" name="loginId" placeholder="아이디 또는 이메일">
        <input id="login-pw" type="password" placeholder="비밀번호">
      </form>`,
    focus: "#login-id",
    expected: {
      kind: "username",
      username: "#login-id",
      password: "#login-pw",
      isSignup: false,
    },
  },
  {
    name: "unlabelled text field right before a password (fallback)",
    html: `
      <form>
        <input id="a" type="text">
        <input id="b" type="password">
      </form>`,
    focus: "#b",
    expected: {
      kind: "password",
      username: "#a",
      password: "#b",
      isSignup: false,
    },
  },
  {
    name: "phone-number login (휴대폰 번호)",
    html: `
      <form>
        <input id="phone" type="tel" placeholder="휴대폰 번호">
        <input id="pw" type="password">
      </form>`,
    focus: "#phone",
    expected: {
      kind: "username",
      username: "#phone",
      password: "#pw",
      isSignup: false,
    },
  },
  {
    name: "step one of a multi-step login (user name only)",
    html: `
      <form>
        <input id="identifier" type="email" autocomplete="username">
        <button>다음</button>
      </form>`,
    focus: "#identifier",
    expected: { kind: "username", username: "#identifier", isSignup: false },
  },
  {
    name: "signup form with password confirmation is never filled",
    html: `
      <form>
        <input id="id" placeholder="아이디">
        <input id="pw1" type="password" placeholder="비밀번호">
        <input id="pw2" type="password" placeholder="비밀번호 확인">
      </form>`,
    focus: "#pw1",
    expected: { kind: undefined, username: "#id", isSignup: true },
  },
  {
    name: "change-password form marked new-password",
    html: `
      <form>
        <input id="new" type="password" autocomplete="new-password">
      </form>`,
    focus: "#new",
    expected: { kind: undefined, isSignup: true },
  },
  {
    name: "hidden decoy password field is ignored",
    html: `
      <form>
        <input id="u" name="username">
        <input id="decoy" type="password" style="display:none">
        <input id="real" type="password">
      </form>`,
    focus: "#real",
    expected: {
      kind: "password",
      username: "#u",
      password: "#real",
      isSignup: false,
    },
  },
  {
    name: "SMS / TOTP code page (인증번호)",
    html: `
      <form>
        <label for="code">인증번호 6자리</label>
        <input id="code" inputmode="numeric" maxlength="6">
      </form>`,
    focus: "#code",
    expected: { kind: "otp", otp: "#code", isSignup: false },
  },
  {
    name: "formless single-page-app login",
    html: `
      <div class="login">
        <input id="user" placeholder="Email">
        <input id="pass" type="password" placeholder="Password">
        <div role="button">Sign in</div>
      </div>`,
    focus: "#user",
    expected: {
      kind: "username",
      username: "#user",
      password: "#pass",
      isSignup: false,
    },
  },
  {
    name: "newsletter email field elsewhere on the page is not a login",
    html: `
      <form id="news"><input id="newsletter" type="text" placeholder="Your name"><button>구독</button></form>`,
    focus: "#newsletter",
    expected: { kind: undefined, isSignup: false },
  },
];
