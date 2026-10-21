#!/usr/bin/env node
// vulndata：漏洞快照只读查询服务。SDK 胶水层，业务逻辑在 src/snapshot.js。
import {
  GrpcError, defineService, grpcInvalidArgumentError, grpcNotFoundError, grpcStatus, runServiceMain,
} from "@chaitin-ai/octobus-sdk";
import { createSnapshotReader } from "../src/snapshot.js";

const errors = {
  invalid: (msg) => grpcInvalidArgumentError(msg),
  notFound: (msg) => grpcNotFoundError(msg),
  failed: (msg) => new GrpcError(grpcStatus.FAILED_PRECONDITION, msg),
};

const reader = (ctx) => createSnapshotReader(ctx.config ?? {}, errors);

const service = defineService({
  handlers: {
    "vulndata.v1.VulndataService/GetSummary": (ctx) => reader(ctx).getSummary(ctx.request ?? {}),
    "vulndata.v1.VulndataService/ListPackages": (ctx) => reader(ctx).listPackages(ctx.request ?? {}),
    "vulndata.v1.VulndataService/GetPackageEvidence": (ctx) => reader(ctx).getPackageEvidence(ctx.request ?? {}),
    "vulndata.v1.VulndataService/GetCVE": (ctx) => reader(ctx).getCve(ctx.request ?? {}),
  },
});

runServiceMain(service);
