using System;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Distributed;

namespace osu.Server.Spectator.Hubs
{
    [UsedImplicitly]
    [Authorize]
    public class SpectatorHub : Hub<ISpectatorClient>, ISpectatorServer
    {
        private readonly IDistributedCache cache;

        public SpectatorHub(IDistributedCache cache)
        {
            this.cache = cache;
        }

        public async Task BeginPlaySession(int beatmapId)
        {
            await updateUserState(beatmapId);

            // let's broadcast to every player temporarily. probably won't stay this way.
            await Clients.All.UserBeganPlaying(Context.UserIdentifier, beatmapId);
        }


        public async Task SendFrameData(FrameDataBundle data)
        {
            var state = await getStateFromUser(Context.UserIdentifier);

            Console.WriteLine($"Receiving frame data (beatmap {state})..");
            await Clients.Group(getGroupId(Context.UserIdentifier)).UserSentFrames(Context.UserIdentifier, data);
        }

        public async Task EndPlaySession(int beatmapId)
        {
            await cache.RemoveAsync(getStateId(Context.UserIdentifier));
            await Clients.All.UserFinishedPlaying(Context.UserIdentifier, beatmapId);
        }

        public async Task StartWatchingUser(string userId)
        {
            Console.WriteLine($"User {Context.UserIdentifier} watching {userId}");

            // send the user's state if exists
            var state = await getStateFromUser(userId);

            if (state.HasValue)
                await Clients.Caller.UserBeganPlaying(userId, state.Value);

            await Groups.AddToGroupAsync(Context.UserIdentifier, getGroupId(userId));
        }

        public async Task EndWatchingUser(string userId)
        {
            await Groups.RemoveFromGroupAsync(Context.UserIdentifier, getGroupId(userId));
        }

        public override async Task OnDisconnectedAsync(Exception exception)
        {
            var state = await getStateFromUser(Context.UserIdentifier);

            if (state.HasValue)
            {
                // clean up user on disconnection
                await EndPlaySession(state.Value);
            }

            await base.OnDisconnectedAsync(exception);
        }

        private async Task updateUserState(int beatmapId) => await cache.SetStringAsync(getStateId(Context.UserIdentifier), beatmapId.ToString());

        private async Task<int?> getStateFromUser(string userId)
        {
            var state = await cache.GetStringAsync(getStateId(userId));

            if (int.TryParse(state, out var intState))
                return intState;

            return null;
        }

        private static string getStateId(string userId) => $"state:{userId}";
        private static string getGroupId(string userId) => $"watch:{userId}";
    }
}