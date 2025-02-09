import type { Site, SocialObjects } from "./types";

export const SITE: Site = {
  website: "https://blog-tanmaypanda.vercel.app/",
  author: "Tanmay Panda",
  profile: "https://tanmaypanda.vercel.app/",
  desc: "A hedonistic blog",
  title: "Tanmay's Blog",
  ogImage: "astropaper-og.png",
  lightAndDarkMode: true,
  postPerIndex: 4,
  postPerPage: 3,
  scheduledPostMargin: 15 * 60 * 1000,
  showArchives: true,
  // editPost: {
  //   url: "https://github.com/tanmaypanda-14/blog/edit/main/src/content/blog",
  //   text: "Suggest Changes",
  //   appendFilePath: true,
  // },
};

export const LOCALE = {
  lang: "en",
  langTag: ["en-EN"], // BCP 47 Language Tags. Set this empty [] to use the environment default
} as const;

export const LOGO_IMAGE = {
  enable: false,
  svg: true,
  width: 216,
  height: 46,
};

export const SOCIALS: SocialObjects = [
  {
    name: "Github",
    href: "https://github.com/tanmaypanda-14/",
    linkTitle: ` ${SITE.title} on Github`,
    active: true,
  },
  {
    name: "LinkedIn",
    href: "https://linkedin.com/in/tanmaypanda-1404/",
    linkTitle: `${SITE.title} on LinkedIn`,
    active: true,
  },
  {
    name: "Mail",
    href: "mailto:tanmay404103@outlook.com",
    linkTitle: `Send an email to ${SITE.title}`,
    active: false,
  },
];
