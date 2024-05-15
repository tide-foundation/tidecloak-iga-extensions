import { lazy } from "react";
import type { AppRouteObject } from "../../routes";

export type UserTab = "list" | "permissions";

export type UsersParams = { realm: string; tab?: UserTab };

const ChangeRequestsSection = lazy(() => import("../ChangeRequestsSection"));

export const ChangeRequestsRoute: AppRouteObject = {
  path: "/:realm/change-requests",
  element: <ChangeRequestsSection />,
  breadcrumb: (t) => t("changeRequestsList"),
  handle: {
    access: "query-users", // update this to some appropriate
  },
};

// export const UsersRouteWithTab: AppRouteObject = {
//   ...UsersRoute,
//   path: "/:realm/users/:tab",
// };

// export const toUsers = (params: UsersParams): Partial<Path> => {
//   const path = params.tab ? UsersRouteWithTab.path : UsersRoute.path;

  // return {
  //   pathname: generateEncodedPath(path, params),
  // };
// };
