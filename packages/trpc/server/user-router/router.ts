import { router } from '../trpc';
import { getUserRoute } from './get-user';

export const userRouter = router({
  get: getUserRoute,
});
